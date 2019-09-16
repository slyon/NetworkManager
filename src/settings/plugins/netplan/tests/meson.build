test_unit = 'test-netplan'

test_netplan_dir = meson.current_source_dir()

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  link_with: libnms_netplan_core,
)

test(
  'netplan/' + test_unit,
  test_script,
  timeout: 90,
  args: test_args + [exe.full_path()],
)
