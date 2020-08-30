
#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

/// Returns the sum of two 16-bit words with an end-around carry,
/// also referred to as one's complement addition.
#[inline]
fn add_with_carry(x: u16, y: u16) -> u16 {
    let sum = (x as u32) + (y as u32);
    ((sum & 0xffff) as u16) + ((sum >> 16) as u16)
}

/// Returns a new Internet checksum computed using the incremental
/// method described in RFC 1624.
#[inline]
unsafe fn recompute_csum(csum: u16, old: u16, new: u16) -> u16 {
    !add_with_carry(add_with_carry(!csum, !old), new)
}

#[xdp]
fn pong(ctx: XdpContext) -> XdpResult {
    let eth = ctx.eth()?;
    let ip = ctx.ip()?;
    let icmp = ctx.icmp()?;

    unsafe {
        let src_mac  = (*eth).h_source;
        let dst_mac  = (*eth).h_dest;
        (*eth).h_source = dst_mac;
        (*eth).h_dest   = src_mac;

        let src_ip = (*ip).saddr;
        let dst_ip = (*ip).daddr;
        (*ip).saddr   = dst_ip;
        (*ip).daddr   = src_ip;

        (*icmp).checksum = recompute_csum((*icmp).checksum, (*icmp).type_ as u16, 0);
        (*icmp).type_ = 0;   // ICMP echo reply
    }

    Ok(XdpAction::Tx)
}
