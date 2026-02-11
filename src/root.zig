const std = @import("std");

pub const Speck32 = @import("speck32.zig").Speck32;
pub const Speck48 = @import("speck48.zig").Speck48;
pub const Speck64 = @import("speck64.zig").Speck64;
pub const Speck96 = @import("speck96.zig").Speck96;
pub const Simon32 = @import("simon32.zig").Simon32;
pub const Simon48 = @import("simon48.zig").Simon48;
pub const Simon64 = @import("simon64.zig").Simon64;
pub const Simon96 = @import("simon96.zig").Simon96;
pub const Simeck32 = @import("simeck32.zig").Simeck32;
pub const Simeck64 = @import("simeck64.zig").Simeck64;
pub const Crax = @import("crax.zig").Crax;

const whitening = @import("whitening.zig");
pub const Speck32Whitened = whitening.Speck32Whitened;
pub const Speck48Whitened = whitening.Speck48Whitened;
pub const Speck64Whitened = whitening.Speck64Whitened;
pub const Speck96Whitened = whitening.Speck96Whitened;
pub const Simon32Whitened = whitening.Simon32Whitened;
pub const Simon48Whitened = whitening.Simon48Whitened;
pub const Simon64Whitened = whitening.Simon64Whitened;
pub const Simon96Whitened = whitening.Simon96Whitened;
pub const Simeck32Whitened = whitening.Simeck32Whitened;
pub const Simeck64Whitened = whitening.Simeck64Whitened;
pub const CraxWhitened = whitening.CraxWhitened;
