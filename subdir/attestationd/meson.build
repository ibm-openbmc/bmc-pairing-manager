
# Define the executable


executable('attestationd',
  'src/spdmlite.cpp',
  dependencies: [provisioning_dep],
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
        'DEFAULT_BUSNAME': 'xyz.openbmc_project.spdm',
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)
install_data(
    'service/xyz.openbmc_project.attestation.conf',
    install_dir: '/etc/dbus-1/system.d/',
)
install_data(
    'conf/spdm.conf',
    install_dir: '/var/spdm/',
)
#install_data(
#    'certs/ca.pem',
#    install_dir: '/etc/ssl/certs',
#)
#install_data(
#    'certs/client_cert.pem',
#    'certs/server_cert.pem',
#    'certs/ca.pem',
#    install_dir: '/etc/ssl/certs/https',
#)
#install_data(
#    'certs/client_key.pem',
#    'certs/server_key.pem',
#    'certs/ca_key.pem',
#    install_dir: '/etc/ssl/private',
#)