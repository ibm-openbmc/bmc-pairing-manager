project('bmc-pairing-manager', 'cpp',default_options: ['cpp_std=c++23','buildtype=debugoptimized',])
boost_dep = dependency('boost', version: '>= 1.86', required: true)
openssl_dep = dependency('openssl', version: '>= 3.0', required: true)
sdeventplus_dep = dependency('sdeventplus')
sdbusplus_dep =dependency('sdbusplus')
dbus_interfaces_dep =dependency('phosphor-dbus-interfaces')
bmc_pairing_manager_dep = declare_dependency(
    dependencies:[sdbusplus_dep,sdeventplus_dep,openssl_dep,boost_dep,dbus_interfaces_dep],
    include_directories:['include']
)
bmc_pairing_manager_default_busname = 'xyz.openbmc_project.BmcPairingManager'
configure_file(
    input: 'service/xyz.openbmc_project.bmc-pairing-manager.service.in',
    output: 'xyz.openbmc_project.bmc-pairing-manager.service',
    configuration: {
        'SYSTEMD_TARGET': 'multi-user.target',
        'DEFAULT_BUSNAME': bmc_pairing_manager_default_busname,
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)
executable('bmc-pairing-manager',
  ['src/bmc_pairing_manager.cpp',
  ],
  install: true,
  include_directories:['src'],
  cpp_args: ['-DBOOST_ASIO_DISABLE_THREADS'],
  dependencies:bmc_pairing_manager_dep,
  install_dir: '/usr/bin'
)

install_data('service/xyz.openbmc_project.bmc-pairing-manager.conf',
  install_dir:'/etc/dbus-1/system.d/'
)

install_data(
    'conf/bmc-pairing-manager.conf',
    install_dir: '/var/bmc-pairing-manager/',
)


if (get_option('pingtest') == true)
    # Install network monitor script
    install_data(
        'service/simple-fix-minimal.sh',
        install_dir: '/usr/bin',
        install_mode: 'rwxr-xr-x'
    )
    # Configure and install network monitor service
    configure_file(
        input: 'service/network-monitor.service.in',
        output: 'network-monitor.service',
        configuration: {
            'SYSTEMD_TARGET': 'multi-user.target',
            'CHECK_INTERVAL': '30',
        },
        install: true,
        install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
    )
endif
subdir('subdir')

# Include tests if enabled
if get_option('tests').enabled()
    subdir('test')
endif
