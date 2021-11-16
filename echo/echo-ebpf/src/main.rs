#![no_std]
#![no_main]

use aya_bpf::{
    bindings::sk_action,
    macros::{map, stream_parser, stream_verdict},
    maps::SockMap,
    programs::SkBuffContext,
};

#[map(name = "sockmap")]
static mut SOCKMAP: SockMap = SockMap::with_max_entries(1, 0);

#[stream_parser]
fn stream_parser(ctx: SkBuffContext) -> u32 {
    match { try_stream_parser(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_stream_parser(ctx: SkBuffContext) -> Result<u32, u32> {
    Ok(ctx.len())
}

#[stream_verdict]
fn stream_verdict(ctx: SkBuffContext) -> u32 {
    match unsafe { try_stream_verdict(ctx) } {
        Ok(_) => sk_action::SK_PASS,
        Err(_) => sk_action::SK_DROP,
    }
}

unsafe fn try_stream_verdict(ctx: SkBuffContext) -> Result<u32, u32> {
    match SOCKMAP.redirect_skb(&ctx, 0, 0) as u32 {
        sk_action::SK_PASS => Ok(sk_action::SK_PASS),
        sk_action::SK_DROP => Err(sk_action::SK_DROP),
        _ => Err(sk_action::SK_DROP),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
