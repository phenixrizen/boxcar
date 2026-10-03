// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The VMM's services on the internal vsock ports: [`ServiceRegistry`].
//!
//! The vsock device asks the registry for every guest connection to an
//! internal port (1024 `boxcar.ctl`, 1025 `boxcar.pty`, 1026
//! `boxcar.sensor`) that its rules let through: from a privileged guest
//! source port, and the first to the port since the device was activated.
//! The registry hands it to the service registered at the port, which
//! returns its end of a stream, or turns it down with a reason; a port with
//! no service turns every connection down, and the guest's request is reset
//! and recorded as `no_service`.
//!
//! [`Vmm::new`](crate::vmm::Vmm::new) creates the registry, empty, and
//! hands it to the device; services are registered through
//! [`VmmHandle::services`](crate::lifecycle::VmmHandle::services), before
//! the guest connects or while it runs.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, PoisonError, RwLock};

use boxcar_vsock::services::is_internal;
use boxcar_vsock::{ConnMeta, Deny, InternalServices};

/// A service: given a guest connection, its end of a stream, or why it
/// turns the connection down. It runs on the vsock thread and must not
/// block.
pub type Service = Arc<dyn Fn(ConnMeta) -> Result<UnixStream, Deny> + Send + Sync>;

/// Why a service could not be registered.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The port is not an internal port: guest connections to it never
    /// reach the registry.
    #[error("vsock port {0} is not an internal port (1024 to 1026)")]
    NotInternal(u32),
    /// A service is registered at the port already.
    #[error("vsock port {0} has a service already")]
    Taken(u32),
}

/// The services on the internal vsock ports. Cheap to share: the VMM, its
/// handles and the vsock device hold one `Arc` of it.
#[derive(Default)]
pub struct ServiceRegistry {
    services: RwLock<HashMap<u32, Service>>,
}

impl ServiceRegistry {
    /// A registry with no service.
    pub fn new() -> ServiceRegistry {
        ServiceRegistry::default()
    }

    /// Registers `service` at the internal `port`. A port takes one
    /// service, for the VMM's life.
    pub fn register(&self, port: u32, service: Service) -> Result<(), RegisterError> {
        if !is_internal(port) {
            return Err(RegisterError::NotInternal(port));
        }
        let mut services = self
            .services
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if services.contains_key(&port) {
            return Err(RegisterError::Taken(port));
        }
        services.insert(port, service);
        Ok(())
    }

    /// The internal ports with a service, in order.
    pub fn ports(&self) -> Vec<u32> {
        let services = self.services.read().unwrap_or_else(PoisonError::into_inner);
        let mut ports: Vec<u32> = services.keys().copied().collect();
        ports.sort_unstable();
        ports
    }
}

impl InternalServices for ServiceRegistry {
    fn connect(&self, port: u32, meta: ConnMeta) -> Result<UnixStream, Deny> {
        // The service runs without the lock held: it may register another.
        let service = self
            .services
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&port)
            .cloned()
            .ok_or(Deny::NoService)?;
        service(meta)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn a_new_registry_serves_nothing() {
        let registry = ServiceRegistry::new();
        assert!(registry.ports().is_empty());
        for port in [1024, 1025, 1026] {
            assert_eq!(
                registry.connect(port, ConnMeta { guest_port: 1023 }).err(),
                Some(Deny::NoService)
            );
        }
    }

    #[test]
    fn a_registered_service_takes_its_ports_connections() {
        let registry = ServiceRegistry::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::new(Mutex::new(Vec::new()));
        let (seen2, kept2) = (seen.clone(), kept.clone());
        registry
            .register(
                1024,
                Arc::new(move |meta| {
                    seen2.lock().unwrap().push(meta);
                    let (ours, theirs) = UnixStream::pair().map_err(|_| Deny::NoService)?;
                    kept2.lock().unwrap().push(theirs);
                    Ok(ours)
                }),
            )
            .unwrap();
        assert_eq!(registry.ports(), [1024]);

        let mut stream = registry
            .connect(1024, ConnMeta { guest_port: 1023 })
            .unwrap();
        assert_eq!(*seen.lock().unwrap(), [ConnMeta { guest_port: 1023 }]);
        stream.write_all(b"hello").unwrap();
        let mut got = [0u8; 5];
        kept.lock().unwrap()[0].read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello");
        // Another port is still not served.
        assert_eq!(
            registry.connect(1025, ConnMeta { guest_port: 1022 }).err(),
            Some(Deny::NoService)
        );
    }

    #[test]
    fn only_internal_ports_take_a_service_and_each_only_one() {
        let registry = ServiceRegistry::new();
        let none: Service = Arc::new(|_| Err(Deny::Refused("busy")));
        for port in [0, 1023, 1027, 5000] {
            assert_eq!(
                registry.register(port, none.clone()),
                Err(RegisterError::NotInternal(port))
            );
        }
        registry.register(1025, none.clone()).unwrap();
        assert_eq!(
            registry.register(1025, none.clone()),
            Err(RegisterError::Taken(1025))
        );
        // A service may turn a connection down, with its reason.
        assert_eq!(
            registry.connect(1025, ConnMeta { guest_port: 1022 }).err(),
            Some(Deny::Refused("busy"))
        );
    }

    /// The registry is called without its lock held: a service may
    /// register another from inside the call.
    #[test]
    fn a_service_may_register_another() {
        let registry = Arc::new(ServiceRegistry::new());
        let inner = Arc::clone(&registry);
        registry
            .register(
                1024,
                Arc::new(move |_| {
                    let _ = inner.register(1026, Arc::new(|_| Err(Deny::NoService)));
                    Err(Deny::NoService)
                }),
            )
            .unwrap();
        assert!(registry
            .connect(1024, ConnMeta { guest_port: 1023 })
            .is_err());
        assert_eq!(registry.ports(), [1024, 1026]);
    }
}
