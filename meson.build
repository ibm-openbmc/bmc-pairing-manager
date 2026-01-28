project('provisioningd', 'cpp',default_options: ['cpp_std=c++23','buildtype=debugoptimized',])
boost_dep = dependency('boost', version: '>= 1.86', required: true)
openssl_dep = dependency('openssl', version: '>= 3.0', required: true)
sdeventplus_dep = dependency('sdeventplus')
sdbusplus_dep =dependency('sdbusplus')
dbus_interfaces_dep =dependency('phosphor-dbus-interfaces')
provisioning_dep = declare_dependency(
    dependencies:[sdbusplus_dep,sdeventplus_dep,openssl_dep,boost_dep,dbus_interfaces_dep],
    include_directories:['include']
)
provisioning_default_busname = 'xyz.openbmc_project.Provisioning'
configure_file(
    input: 'service/xyz.openbmc_project.provisioning.service.in',
    output: 'xyz.openbmc_project.provisioning.service',
    configuration: {
        'SYSTEMD_TARGET': 'multi-user.target',
        'DEFAULT_BUSNAME': provisioning_default_busname,
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)
executable('provisioningd',
  ['src/provisioningd.cpp',
  ],
  install: true,
  include_directories:['src'],
  cpp_args: ['-DBOOST_ASIO_DISABLE_THREADS'],
  dependencies:provisioning_dep,
  install_dir: '/usr/bin'
)

install_data('service/xyz.openbmc_project.provisioning.conf',
  install_dir:'/etc/dbus-1/system.d/'
)

install_data(
    'conf/provisioning.conf',
    install_dir: '/var/provisioning/',
)
subdir('subdir')