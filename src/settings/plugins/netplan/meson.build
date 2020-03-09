sources = files(
  'nms-netplan-utils.c',
  'nms-netplan-storage.c',
  'nms-netplan-writer.c',
  'nms-netplan-reader.c',
)

deps = [
  glib_dep,
  nm_dep,
]

libnms_netplan_core = static_library(
  'nms-netplan-core',
  sources: sources,
  dependencies: deps,
)

sources = files(
  'nms-netplan-plugin.c',
)

libnm_settings_plugin_netplan = shared_module(
  'nm-settings-plugin-netplan',
  sources: sources,
  dependencies: deps,
  link_with: libnms_netplan_core,
  link_args: [
    ldflags_linker_script_settings,
    '-lnetplan',
  ],
  link_depends: linker_script_settings,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_settings_plugin_netplan

# FIXME: check_so_symbols replacement
'''
run_target(
  'check-local-symbols-settings-netplan',
  command: [check_so_symbols, libnm_settings_plugin_netplan.full_path()],
  depends: libnm_settings_plugin_netplan,
)

check-local-symbols-settings-netplan: src/settings/plugins/netplan/libnm-settings-plugin-netplan.la
  $(call check_so_symbols,$(builddir)/src/settings/plugins/netplan/.libs/libnm-settings-plugin-netplan.so)
'''
