
# Define the executable


executable('attestationd',
  'src/attestation.cpp',
  dependencies: [bmc_pairing_manager_dep],
  cpp_args: ['-DBOOST_ASIO_DISABLE_THREADS'],
  include_directories:['src'],
  install: true,
  install_dir: '/usr/bin'
)
configure_file(
    input: 'service/xyz.openbmc_project.attestation.service.in',
    output: 'xyz.openbmc_project.attestation.service',
    configuration: {
        'SYSTEMD_TARGET': 'multi-user.target',
        'DEFAULT_BUSNAME': 'xyz.openbmc_project.attestation',
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)
install_data(
    'service/xyz.openbmc_project.attestation.conf',
    install_dir: '/etc/dbus-1/system.d/',
)
install_data(
    'conf/attestation.conf',
    install_dir: '/var/attestation/',
)
