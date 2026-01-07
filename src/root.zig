const std = @import("std");

pub const Speck32 = @import("speck32.zig").Speck32;
pub const Speck64 = @import("speck64.zig").Speck64;
pub const Simon32 = @import("simon32.zig").Simon32;
pub const Simon64 = @import("simon64.zig").Simon64;
pub const Simeck32 = @import("simeck32.zig").Simeck32;
pub const Simeck64 = @import("simeck64.zig").Simeck64;

const whitening = @import("whitening.zig");
pub const Speck32Whitened = whitening.Speck32Whitened;
pub const Speck64Whitened = whitening.Speck64Whitened;
pub const Simon32Whitened = whitening.Simon32Whitened;
pub const Simon64Whitened = whitening.Simon64Whitened;
pub const Simeck32Whitened = whitening.Simeck32Whitened;
pub const Simeck64Whitened = whitening.Simeck64Whitened;
