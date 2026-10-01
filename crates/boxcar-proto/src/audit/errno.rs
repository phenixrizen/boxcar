// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Linux errno names, for the `err` field of `OpResult`.

/// The symbolic name of a Linux errno number, such as `13` -> `"EACCES"`, or
/// `None` for a number Linux does not define (zero, negatives, the unassigned
/// 41 and 58, anything past 133).
///
/// These are the numbers of the Linux `asm-generic` table, which is what a
/// FUSE reply carries and what the x86-64 and aarch64 guests use. Where the
/// kernel gives one number several names, the kernel's own spelling wins:
/// 11 is `EAGAIN` (not `EWOULDBLOCK`), 35 is `EDEADLK`, 95 is `EOPNOTSUPP`.
pub(super) fn name(errno: i32) -> Option<&'static str> {
    let symbol = match errno {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        15 => "ENOTBLK",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        26 => "ETXTBSY",
        27 => "EFBIG",
        28 => "ENOSPC",
        29 => "ESPIPE",
        30 => "EROFS",
        31 => "EMLINK",
        32 => "EPIPE",
        33 => "EDOM",
        34 => "ERANGE",
        35 => "EDEADLK",
        36 => "ENAMETOOLONG",
        37 => "ENOLCK",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        42 => "ENOMSG",
        43 => "EIDRM",
        44 => "ECHRNG",
        45 => "EL2NSYNC",
        46 => "EL3HLT",
        47 => "EL3RST",
        48 => "ELNRNG",
        49 => "EUNATCH",
        50 => "ENOCSI",
        51 => "EL2HLT",
        52 => "EBADE",
        53 => "EBADR",
        54 => "EXFULL",
        55 => "ENOANO",
        56 => "EBADRQC",
        57 => "EBADSLT",
        59 => "EBFONT",
        60 => "ENOSTR",
        61 => "ENODATA",
        62 => "ETIME",
        63 => "ENOSR",
        64 => "ENONET",
        65 => "ENOPKG",
        66 => "EREMOTE",
        67 => "ENOLINK",
        68 => "EADV",
        69 => "ESRMNT",
        70 => "ECOMM",
        71 => "EPROTO",
        72 => "EMULTIHOP",
        73 => "EDOTDOT",
        74 => "EBADMSG",
        75 => "EOVERFLOW",
        76 => "ENOTUNIQ",
        77 => "EBADFD",
        78 => "EREMCHG",
        79 => "ELIBACC",
        80 => "ELIBBAD",
        81 => "ELIBSCN",
        82 => "ELIBMAX",
        83 => "ELIBEXEC",
        84 => "EILSEQ",
        85 => "ERESTART",
        86 => "ESTRPIPE",
        87 => "EUSERS",
        88 => "ENOTSOCK",
        89 => "EDESTADDRREQ",
        90 => "EMSGSIZE",
        91 => "EPROTOTYPE",
        92 => "ENOPROTOOPT",
        93 => "EPROTONOSUPPORT",
        94 => "ESOCKTNOSUPPORT",
        95 => "EOPNOTSUPP",
        96 => "EPFNOSUPPORT",
        97 => "EAFNOSUPPORT",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        100 => "ENETDOWN",
        101 => "ENETUNREACH",
        102 => "ENETRESET",
        103 => "ECONNABORTED",
        104 => "ECONNRESET",
        105 => "ENOBUFS",
        106 => "EISCONN",
        107 => "ENOTCONN",
        108 => "ESHUTDOWN",
        109 => "ETOOMANYREFS",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        112 => "EHOSTDOWN",
        113 => "EHOSTUNREACH",
        114 => "EALREADY",
        115 => "EINPROGRESS",
        116 => "ESTALE",
        117 => "EUCLEAN",
        118 => "ENOTNAM",
        119 => "ENAVAIL",
        120 => "EISNAM",
        121 => "EREMOTEIO",
        122 => "EDQUOT",
        123 => "ENOMEDIUM",
        124 => "EMEDIUMTYPE",
        125 => "ECANCELED",
        126 => "ENOKEY",
        127 => "EKEYEXPIRED",
        128 => "EKEYREVOKED",
        129 => "EKEYREJECTED",
        130 => "EOWNERDEAD",
        131 => "ENOTRECOVERABLE",
        132 => "ERFKILL",
        133 => "EHWPOISON",
        _ => return None,
    };
    Some(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn common_filesystem_errnos_have_their_linux_names() {
        for (number, want) in [
            (1, "EPERM"),
            (2, "ENOENT"),
            (5, "EIO"),
            (9, "EBADF"),
            (11, "EAGAIN"),
            (12, "ENOMEM"),
            (13, "EACCES"),
            (17, "EEXIST"),
            (18, "EXDEV"),
            (20, "ENOTDIR"),
            (21, "EISDIR"),
            (22, "EINVAL"),
            (24, "EMFILE"),
            (28, "ENOSPC"),
            (30, "EROFS"),
            (36, "ENAMETOOLONG"),
            (38, "ENOSYS"),
            (39, "ENOTEMPTY"),
            (40, "ELOOP"),
            (61, "ENODATA"),
            (95, "EOPNOTSUPP"),
            (116, "ESTALE"),
            (122, "EDQUOT"),
            (133, "EHWPOISON"),
        ] {
            assert_eq!(name(number), Some(want), "errno {number}");
        }
    }

    #[test]
    fn numbers_outside_the_linux_table_have_no_name() {
        // 41 and 58 are unassigned on Linux; 0 is success, not an error.
        for number in [0, -2, 41, 58, 134, 4096, i32::MIN, i32::MAX] {
            assert_eq!(name(number), None, "errno {number}");
        }
    }

    #[test]
    fn every_name_is_used_once() {
        let names: Vec<&str> = (1..=133).filter_map(name).collect();
        assert_eq!(names.len(), 131, "133 numbers minus the holes at 41 and 58");
        let unique: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len());
    }
}
