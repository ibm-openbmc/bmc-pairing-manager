executable(
    'lldp-hosts-updater',
    'src/lldp_hosts_updater.cpp',
    dependencies: [bmc_pairing_manager_dep],
    cpp_args: ['-DBOOST_ASIO_DISABLE_THREADS'],
    include_directories: ['include'],
    install: true,
    install_dir: '/usr/bin',
)

configure_file(
    input: 'service/xyz.openbmc_project.lldp-hosts-updater.service.in',
    output: 'xyz.openbmc_project.lldp-hosts-updater.service',
    configuration: {
        'IFACE': get_option('lldp_hosts_updater_iface'),
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)
