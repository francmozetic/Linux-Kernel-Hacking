#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x75193b8b, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xf7e4c997, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x66d13e89, __VMLINUX_SYMBOL_STR(netlink_has_listeners) },
	{ 0xee5bca2a, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0x97255bdf, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x96424867, __VMLINUX_SYMBOL_STR(single_release) },
	{ 0xa1d55e90, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0x1247444, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0xc7318a72, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xdf3d590b, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0x328a05f1, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x5029b962, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0xe2b3b11b, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x2c34f2ef, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0x4a49fdc, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x3bb1186a, __VMLINUX_SYMBOL_STR(netlink_broadcast) },
	{ 0xdd3916ac, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0x202f68fd, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x9248ac50, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0x34410ea0, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0xf2fdccab, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x9d669763, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xb81960ca, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0xfffd187c, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4B42A038F815F00B7B0DD01");
