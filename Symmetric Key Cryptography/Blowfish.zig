const u = @import("../utils.zig");

pub const Blowfish = struct {
    p: [18]u32,
    s: [4][256]u32,

    const ORIG_P = [18]u32{
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
        0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b,
    };

    const ORIG_S = [4][256]u32{
        .{
            0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
            0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
            0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
            0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
            0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
            0x6c9e0e8b, 0xb01e8a3f, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
            0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
            0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636f8020,
            0x6902d890, 0xc4b52b27, 0xd28e7729, 0x6a23e473, 0x31c4a1e2, 0x6d6d6d0d,
            0x24cc7b91, 0x8327b242, 0x82355641, 0x63189e23, 0x5933e180, 0x33ee4a6b,
            0x15c0d27c, 0x59e4d7c0, 0x18d48763, 0x6b3bb6d1, 0x645c4b6b, 0x5cc6686a,
            0x61b2b894, 0x77834059, 0x9e08dcc0, 0x0e4c4aaa, 0x72460505, 0xde769f28,
            0xc913e934, 0xd1d3d8c7, 0x614c7f6e, 0x55c8d645, 0x63be61d8, 0x73d59e44,
            0xb8e1af7e, 0xee4d739e, 0x7b2bc5af, 0xa3e5f312, 0x4700ee30, 0x2252f62c,
            0x20ac9900, 0x0d4aaddd, 0x6200f81f, 0x3d7a9e1e, 0x8e930f64, 0x50e92354,
            0x0a2bf57b, 0x080e4177, 0xf6e7a926, 0xe0ebe01c, 0x9e6b3f4b, 0xb2ef8a4b,
            0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7d1a0b65, 0x2ba68295, 0x9ddba3bc,
            0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4,
            0x5c8fe5e3, 0x7d1a0b65, 0x2ba68295, 0x9ddba3bc, 0x7b3f9bc2, 0x1b5b879d,
            0x7d1a0b65, 0x6e2a5d94, 0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d,
            0x7d1a0b65, 0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7d1a0b65,
            0x2ba68295, 0x9ddba3bc, 0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94,
            0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94,
            0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65,
            0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d,
            0x7d1a0b65, 0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2,
            0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3,
            0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4,
            0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94, 0x5a419a4a,
            0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94,
            0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d, 0x7d1a0b65,
            0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2, 0x1b5b879d,
            0x7d1a0b65, 0x6e2a5d94, 0x5a419a4a, 0xd8d9e4c4, 0x5c8fe5e3, 0x7b3f9bc2,
            0x1b5b879d, 0x7d1a0b65, 0x6e2a5d94,
        },
        .{
            0x7a4d6c50, 0x2d9a8b7f, 0x4e5c1d3a, 0x8f2b6e91, 0xc0d7a345, 0x1e6f9b28,
            0x5d3a8c74, 0xb72e4f01, 0x9c1d5e86, 0x3b8a4d6f, 0xe2f0c759, 0xa56d3e4b,
            0x08c9721d, 0xf4b68e53, 0x6d2a9f15, 0x8b3c7e40, 0x1a5d6f92, 0xc7e03b48,
            0x5f9a2d6e, 0x3c4b8f17, 0xa2d5e671, 0x9e1b4c86, 0xd0f3a725, 0x6b8e2c49,
            0xf57a1d03, 0x4c9e6b28, 0x83d2a5f6, 0x1e7b4c9d, 0x5a2f8e36, 0xc94d7b10,
            0x7f6e2a45, 0xb8c1d39e, 0x2d5a4f77, 0xe196b0c8, 0x4b8e3f2d, 0xa5c79160,
            0xf03d8e4b, 0x6c2a9d15, 0x1b7e4f83, 0xd960a2c5, 0x5e3b7c48, 0x9a4d1f26,
            0xc8f20e73, 0x07e5b619, 0x3d8a4c5f, 0xb12e6f94, 0x6e9c0d37, 0xf4a8512b,
            0x2c7d9b40, 0x8f3e5a16, 0xa4b7c029, 0x5d1e9f63, 0x3a6b2c78, 0xe0f4d751,
            0xc2986b0f, 0x1d5a7e34, 0x9b3f4c82, 0x76e0a21d, 0x4c8f5b36, 0xb5d29047,
            0x2a7e1c59, 0xf86b3d04, 0x614e9a28, 0xd3c50f79, 0x0e8b4d52, 0xc7a32f68,
            0x5b9e1d40, 0xa2f68c37, 0x3d4b7e95, 0x8c1a5f26, 0x4f7e0b19, 0xd6a329e5,
            0x1c8f5a73, 0x9e4b2d06, 0x7a5c1e84, 0xb3f06d29, 0x5e2a8c47, 0x0d3b7f61,
            0xc694a258, 0xf18e3b7d, 0x2d4a6c90, 0x8b5f1e36, 0xa7c3924d, 0x4e0f8b52,
            0x6d3a7c19, 0xf5b82e40, 0x3c9d1a67, 0xb14f6e28, 0x9a0c5d73, 0xe72f4b81,
            0x5d8a3c46, 0x0b1e6f92, 0xc84d5a37, 0x7f2b9e60, 0x2e5a1c8d, 0xd3b6f049,
            0x6a4c9e15, 0xf1873b52, 0x4e9d0a6c, 0xb52f1d78, 0xa0c3846e, 0x1d7b5f93,
            0x8e4a2c05, 0x5c3f9d71, 0x3a6b0e82, 0xc79f4d16, 0xf2d08b4e, 0x6e1a5c39,
            0x9b4d7f20, 0x0a8c3e56, 0xd5f16a28, 0x7c3e4b91, 0x2f8a5d04, 0xb1690c47,
            0x4e7c3a5f, 0xa5d29e16, 0xf08b6c43, 0x6d1a4b85, 0xc3920f7e, 0x1e5b8a64,
            0x8b4d2c30, 0x5a7f9e16, 0x3e0b6c82, 0xd7a41f59, 0x9c5e2b40, 0x064f8a3d,
            0xf13b7e52, 0x4a9c5d68, 0xb5e06127, 0x2c7a4f93, 0x8d3b6e10, 0x5e1a9f47,
            0x7b0c5d62, 0xc4f28a3e, 0x1d6b4f95, 0xa9837c20, 0xf3540e6b, 0x6c2a9d18,
            0x3b8e5f74, 0xd0914c6a, 0x9f2b7e05, 0x0e4c3d69, 0x7a5b1f82, 0xc6d08347,
            0x4e9a2b16, 0xb3f17c58, 0x2d5e6a03, 0x8c1b4f79, 0x5f7a3e60, 0x1c0d9b45,
            0xa4623f78, 0xf08e5c2b, 0x6d4b1a97, 0xc95e3d04, 0x3a7f2e58, 0xb01c4d69,
            0x4e8a6f25, 0xd2b57094, 0x9c3f8a1e, 0x0d5b4e67, 0x7b2a9c50, 0xc1483f6e,
            0x5a9d2b07, 0x8e7c4f31, 0x2d6a1b94, 0xf30e5c78, 0x6b4f8a25, 0xa1973d40,
            0x4e0c5b96, 0xd7f28e13, 0x3b5a6c07, 0xc8194e5f, 0x9a2d7b60, 0x0f4c8e35,
            0x7e5b1a69, 0xb3d04c82, 0x5f6a9e14, 0x2c4b8d70, 0xa0385f1e, 0xd6c94b27,
            0x6e1a4f83, 0xf4920b5c, 0x1d8c3e6a, 0x8b5f7a24, 0x4e2c1d96, 0xc7a30f58,
            0x5b9e6d40, 0x3a0f8c17, 0xb2d64e91, 0x9f1a5c04, 0x0c4e7b52, 0x7d2a4860,
            0xf06b3e15, 0xa4812c97,
        },
        .{
            0x2d8a5c71, 0xf07b4e93, 0x9c1d6a58, 0x4e5b2f07, 0xb38e7a60, 0x6c2d1f84,
            0xd4a05e29, 0x1b8c3f76, 0x8e5a9c42, 0x5f7b0d13, 0x3a4e6c97, 0xc9120f58,
            0xa06d5b3e, 0x0f8c7a24, 0x7b1e9d56, 0xe2048b6f, 0x5c3a9d18, 0xd67e4b02,
            0x2f1a8c75, 0x9b4e6d30, 0x4a7c5f19, 0xc0d38b56, 0x8e2a4d71, 0x1f5b6c93,
            0x7a3d8e05, 0xb94c1f62, 0x5e063a8d, 0x3c9d2b47, 0xd1487f5a, 0xa27e0c96,
            0x0b5f3d81, 0xf16a4e23, 0x6d8c2b50, 0xc94f0a67, 0x4e5b1d38, 0x8a7c6f29,
            0x2b4d9e15, 0x9f1a6c08, 0xd38e7b46, 0x5c0a4f92, 0x7e2b1d64, 0xb1563a0f,
            0x3d8c5e71, 0xc0f26a49, 0x6a4d1b85, 0xf2874c30, 0x1e9b5d63, 0xa5c02f78,
            0x4b8e7a16, 0x9d2c4f50, 0xd7a83b61, 0x0f5e6c24, 0x7c1a8d59, 0xe3065b48,
            0x5a2f9c17, 0xc8940d6b, 0x3b7e2a54, 0xb15d0c68, 0x8f4a6e23, 0x2c9b1d70,
            0x6e0a4f85, 0xf4d27c19, 0x1a8b3e56, 0xa74c5f02, 0x4e9d6b38, 0xd05f8c71,
            0x9b3a0e64, 0x072c5d8f, 0x7e4b1a53, 0xc58f6d20, 0x5d1a9b46, 0x2f8c4e37,
            0xb04d7a19, 0x8e5c3f62, 0x3a9b0d54, 0xd6c71e40, 0x4f5a8b26, 0xa18e3c95,
            0xf02d4b68, 0x1c7a9e53, 0x6b4d0f82, 0xc93e5a16, 0x5f8b2d47, 0x9a0e6c31,
            0xd45c1b78, 0x0b2a7f64, 0x7e3c8b15, 0xe14d5a29, 0x58c93f06, 0x2d6a4e80,
            0xb1975c34, 0x8f0a6d52, 0x3c5b1e79, 0xc4072a6e, 0x5a9f4d13, 0xa36b0e84,
            0xf1843c57, 0x1d5e6b92, 0x6c2f9a48, 0xc8b40d75, 0x4e7a1f63, 0x9d3b5c06,
            0xd08e4a27, 0x0a5f7b14, 0x7c2d6e83, 0xe5a03b46, 0x5b1c8f29, 0x2e7a3d50,
            0xb4690c18, 0x895f1e64, 0x3e0a5d72, 0xcb4d7f30, 0x5c8e2a16, 0xa73b4e91,
            0xf2960d53, 0x1b4c8e75, 0x6d5a2f08, 0xc10e4b36, 0x4a7d8e59, 0x9c3f1a47,
            0xd8625c0b, 0x029e4b78, 0x7f1a6d43, 0xe5802c19, 0x534b8f60, 0x2d7e4a05,
            0xb80c5d37, 0x8a4f1e62, 0x3d5b9c14, 0xc62f7a08, 0x4e195d83, 0xa0823f57,
            0xf54c6b10, 0x1e9a7d42, 0x680f4c35, 0xc3b78e19, 0x4a5d2f70, 0x9b1e0a64,
            0xd7405c18, 0x058e3b76, 0x7c4a1d93, 0xe12f5b04, 0x569c0d27, 0x2b8a4e61,
            0xbe1d5f73, 0x8d0c6a45, 0x3a9b2e10, 0xc57d4f86, 0x4f1e8a32, 0xa26b7c09,
            0xf0304d15, 0x1c8e6b74, 0x695a2c03, 0xcb4e7f50, 0x492d0a86, 0x9e3b1c47,
            0xd08a5f62, 0x07c63b19, 0x7a5e4d84, 0xe2f10a35, 0x54c98b62, 0x2a7d4e10,
            0xbd0e5f86, 0x8c4a1b53, 0x3f6e2d09, 0xc10b4a75, 0x4d8c3e62, 0xa1570b94,
            0xf26a4c18, 0x1b9e5d37, 0x6d2f8a40, 0xc9401e5b, 0x485b7c06, 0x9e0a3d81,
            0xd35c1f74, 0x04b86e29, 0x7d2a9c50, 0xe4f35b16, 0x571e8a43, 0x2c5f0d68,
            0xbe843a15, 0x8a6d4c37, 0x3e1b5f09, 0xc74e0a62, 0x4c9d3b85, 0xa04e6f17,
            0xf15a8d34, 0x1d7b4c50, 0x6a2e9f08, 0xc80d4b63, 0x473f5a91, 0x9d1b0e26,
            0xd2c45f18, 0x0a8e6b43, 0x7f3c1d50, 0xe4a72c86, 0x583b0f92, 0x2b9e4d60,
        },
        .{
            0xf04e1a8c, 0x6b3d5c07, 0xc9824e15, 0x2a5b7f60, 0x8d1e0c43, 0x5a7f9b24,
            0xd4c01a6e, 0x1b8e3d57, 0x7c6a4f82, 0xe2095d13, 0x4e8b2a76, 0xb15f0c39,
            0x9d2e7a40, 0x0a4c6f18, 0x3d7b1e54, 0xc5a02b69, 0x6f1d4c85, 0xf2873a10,
            0x2c4b8e57, 0x9a0d5f63, 0x4e6b1a38, 0xb73c9d05, 0xd08a4e61, 0x1f5b6c27,
            0x7a2e4d93, 0xe14c8b50, 0x58a93f26, 0x2d6a7e14, 0xb4f01c85, 0x8c3e5a69,
            0x3b7d0f42, 0xc0195a86, 0x6e5c2b73, 0xf49a0d18, 0x2e1b8c54, 0x9f4d6a07,
            0x4a8e3f25, 0xb50c7d61, 0xd72a4e10, 0x1c5b8f36, 0x7d3a6e92, 0xe80c1b47,
            0x5a2f9d60, 0x2b7e4c18, 0xb8430a6f, 0x8e5d1c74, 0x3c6a0f29, 0xc14b8e56,
            0x6a9d2e03, 0xf0573a4c, 0x2d8c1b65, 0x9c4f0e72, 0x4b1a6d58, 0xb07e3c14,
            0xd63f4a80, 0x1a8b5e27, 0x7f4c9d35, 0xe12a6b04, 0x5c8e3f16, 0x290d4b83,
            0xb65e1a74, 0x8a3c7f02, 0x3d4b8c91, 0xc7f25e60, 0x6b0a1d43, 0xf18c4b25,
            0x204e9a37, 0x9e3d5c18, 0x4a7b0f62, 0xb3824c15, 0xd15e0a79, 0x0c8b6e43,
            0x7d2f4a56, 0xe59c1b28, 0x5e0a4d70, 0x2b7c3f19, 0xb4185e62, 0x893c6a04,
            0x3f5b1d87, 0xc2a04b56, 0x6c1e7a39, 0xf0482b15, 0x219d4e83, 0x9a0b5c26,
            0x4e8f1d50, 0xb26c0a47, 0xd0843e91, 0x0f5b7a62, 0x7c1d4b35, 0xe3a08c19,
            0x5d2b6f04, 0x28a43e76, 0xbe517c03, 0x8b4d0f62, 0x3e1a5c97, 0xc6b02d48,
            0x6a4f0b15, 0xf2893c74, 0x205d6e83, 0x9c1a4b07, 0x4f6e8d52, 0xb17a0c39,
            0xd3924e16, 0x0a5b7c84, 0x7e4d1f20, 0xe1065c78, 0x5b8a3e42, 0x2c4d6f15,
            0xb8039a64, 0x8d7c1e50, 0x3f4b5a29, 0xc01e8d73, 0x6e5a2b04, 0xf63c7d18,
            0x219e4a85, 0x9b0f3c74, 0x4c8d6e12, 0xb25a1f60, 0xd14b0e38, 0x0f7c3a56,
            0x7a1e9c42, 0xe4b05d16, 0x583a4f80, 0x2d6b0c94, 0xbef17a03, 0x8a5c2d46,
            0x3c0e1b79, 0xc74a5f13, 0x6b1e8c50, 0xf12d4a67, 0x24857e90, 0x9d3a6b05,
            0x4e5f0c82, 0xb0863d17, 0xd2591a4e, 0x0b3c7f62, 0x7c4e5d38, 0xe1a70f25,
            0x5c6b2a14, 0x29f04d83, 0xb67a0e51, 0x8e2c5b40, 0x3d9f1c06, 0xc14a6e82,
            0x6f5b0d37, 0xf08c2a49, 0x274e9b15, 0x9a0d5e63, 0x4b7c1f28, 0xb15e3a06,
            0xd3840c72, 0x0c2b7e54, 0x7f4d6a18, 0xe3b01c95, 0x5a8f2d06, 0x2e6a7b43,
            0xb9420e16, 0x8c5d1a70, 0x3e4b7f29, 0xc7a05d14, 0x6d2c8b03, 0xf0164e58,
            0x258a3c71, 0x9c1f4b65, 0x4a7e0d82, 0xb24c6a17, 0xd0715e03, 0x0e8b3c46,
            0x7d2f5a91, 0xe4960c28, 0x5b3a1f74, 0x2c0d8e56, 0xba5c1d37, 0x8f4e6a02,
            0x3d7b5e14, 0xc52a8f60, 0x6b0e1c43, 0xf3847d29, 0x261b5a08, 0x9f4c3d71,
            0x4e8a1b53, 0xb07f6c14, 0xd45a0e89, 0x093c7e26, 0x7c1b5f40, 0xe20d8a53,
            0x5a6e3c17, 0x2b4f0d85, 0xb8691e04, 0x8d3c7a56, 0x3c5e2b91, 0xc14a0d68,
            0x6f2b5e43, 0xf1980c25, 0x274a9d18, 0x9e0b4c63, 0x4b7a1d80, 0xb25e4f07,
        },
    };

    fn f(b: *Blowfish, x: u32) u32 {
        const h = (b.s[0][(x >> 24) & 0xFF] +% b.s[1][(x >> 16) & 0xFF]) ^ b.s[2][(x >> 8) & 0xFF];
        return h +% b.s[3][x & 0xFF];
    }

    pub fn init(key: []const u8) Blowfish {
        var bf = Blowfish{ .p = ORIG_P, .s = ORIG_S };
        var j: usize = 0;
        var i: usize = 0;
        while (i < 18) : (i += 1) {
            var data: u32 = 0;
            var k: usize = 0;
            while (k < 4) : (k += 1) {
                data = (data << 8) | @as(u32, key[j % key.len]);
                j += 1;
            }
            bf.p[i] ^= data;
        }
        var l: u32 = 0;
        var r: u32 = 0;
        i = 0;
        while (i < 18) : (i += 2) {
            const enc = encryptPair(&bf, l, r);
            l = enc[0];
            r = enc[1];
            bf.p[i] = l;
            bf.p[i + 1] = r;
        }
        i = 0;
        while (i < 4) : (i += 1) {
            var j2: usize = 0;
            while (j2 < 256) : (j2 += 2) {
                const enc = encryptPair(&bf, l, r);
                l = enc[0];
                r = enc[1];
                bf.s[i][j2] = l;
                bf.s[i][j2 + 1] = r;
            }
        }
        return bf;
    }

    pub fn encryptPair(b: *Blowfish, xl: u32, xr: u32) [2]u32 {
        var xleft = xl;
        var xright = xr;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            xleft ^= b.p[i];
            xright ^= f(b, xleft);
            const tmp = xleft;
            xleft = xright;
            xright = tmp;
        }
        const tmp2 = xleft;
        xleft = xright;
        xright = tmp2;
        xright ^= b.p[16];
        xleft ^= b.p[17];
        return .{ xleft, xright };
    }

    pub fn decryptPair(b: *Blowfish, xl: u32, xr: u32) [2]u32 {
        var xleft = xl;
        var xright = xr;
        var i: usize = 17;
        while (i > 1) : (i -= 1) {
            xleft ^= b.p[i];
            xright ^= f(b, xleft);
            const tmp = xleft;
            xleft = xright;
            xright = tmp;
        }
        const tmp2 = xleft;
        xleft = xright;
        xright = tmp2;
        xright ^= b.p[1];
        xleft ^= b.p[0];
        return .{ xleft, xright };
    }

    pub fn encryptBlock(b: *Blowfish, block: *const [8]u8) [8]u8 {
        const xl = @as(u32, block[0]) << 24 | @as(u32, block[1]) << 16 | @as(u32, block[2]) << 8 | @as(u32, block[3]);
        const xr = @as(u32, block[4]) << 24 | @as(u32, block[5]) << 16 | @as(u32, block[6]) << 8 | @as(u32, block[7]);
        const result = b.encryptPair(xl, xr);
        var out: [8]u8 = undefined;
        out[0] = @truncate(result[0] >> 24);
        out[1] = @truncate(result[0] >> 16);
        out[2] = @truncate(result[0] >> 8);
        out[3] = @truncate(result[0]);
        out[4] = @truncate(result[1] >> 24);
        out[5] = @truncate(result[1] >> 16);
        out[6] = @truncate(result[1] >> 8);
        out[7] = @truncate(result[1]);
        return out;
    }

    pub fn decryptBlock(b: *Blowfish, block: *const [8]u8) [8]u8 {
        const xl = @as(u32, block[0]) << 24 | @as(u32, block[1]) << 16 | @as(u32, block[2]) << 8 | @as(u32, block[3]);
        const xr = @as(u32, block[4]) << 24 | @as(u32, block[5]) << 16 | @as(u32, block[6]) << 8 | @as(u32, block[7]);
        const result = b.decryptPair(xl, xr);
        var out: [8]u8 = undefined;
        out[0] = @truncate(result[0] >> 24);
        out[1] = @truncate(result[0] >> 16);
        out[2] = @truncate(result[0] >> 8);
        out[3] = @truncate(result[0]);
        out[4] = @truncate(result[1] >> 24);
        out[5] = @truncate(result[1] >> 16);
        out[6] = @truncate(result[1] >> 8);
        out[7] = @truncate(result[1]);
        return out;
    }

    pub fn encrypt(b: *Blowfish, data: []u8) void {
        var i: usize = 0;
        while (i + 8 <= data.len) : (i += 8) {
            var block: [8]u8 = undefined;
            u.copyBytes(&block, data[i .. i + 8]);
            const enc = b.encryptBlock(&block);
            u.copyBytes(data[i .. i + 8], &enc);
        }
    }

    pub fn decrypt(b: *Blowfish, data: []u8) void {
        var i: usize = 0;
        while (i + 8 <= data.len) : (i += 8) {
            var block: [8]u8 = undefined;
            u.copyBytes(&block, data[i .. i + 8]);
            const dec = b.decryptBlock(&block);
            u.copyBytes(data[i .. i + 8], &dec);
        }
    }
};

test "Blowfish encrypt/decrypt roundtrip" {
    var bf = Blowfish.init("testkey");
    var data = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const orig = data;
    bf.encrypt(&data);
    bf.decrypt(&data);
    for (data, orig) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "Blowfish block encrypt/decrypt roundtrip" {
    var bf = Blowfish.init("TESTKEY_8BYTES");
    const pt = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const ct = bf.encryptBlock(&pt);
    const dt = bf.decryptBlock(&ct);
    for (dt, pt) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}
