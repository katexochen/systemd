# SPDX-License-Identifier: LGPL-2.1-or-later

libsystemd_network_sources = files(
        'arp-util.c',
        'dhcp-network.c',
        'dhcp-option.c',
        'dhcp-packet.c',
        'dhcp6-network.c',
        'dhcp6-option.c',
        'dhcp6-protocol.c',
        'icmp6-packet.c',
        'icmp6-util.c',
        'lldp-neighbor.c',
        'lldp-network.c',
        'ndisc-option.c',
        'network-common.c',
        'network-internal.c',
        'sd-dhcp-client-id.c',
        'sd-dhcp-client.c',
        'sd-dhcp-duid.c',
        'sd-dhcp-lease.c',
        'sd-dhcp-server-lease.c',
        'sd-dhcp-server.c',
        'sd-dhcp6-client.c',
        'sd-dhcp6-lease.c',
        'sd-dns-resolver.c',
        'sd-ipv4acd.c',
        'sd-ipv4ll.c',
        'sd-lldp-rx.c',
        'sd-lldp-tx.c',
        'sd-ndisc.c',
        'sd-ndisc-neighbor.c',
        'sd-ndisc-redirect.c',
        'sd-ndisc-router.c',
        'sd-ndisc-router-solicit.c',
        'sd-radv.c',
)

sources += libsystemd_network_sources

libsystemd_network = static_library(
        'systemd-network',
        libsystemd_network_sources,
        include_directories : includes,
        implicit_include_directories : false,
        dependencies : userspace,
        build_by_default : false)

libsystemd_network_includes = [includes, include_directories('.')]

############################################################

network_test_template = test_template + {
        'link_with' : [
                libshared,
                libsystemd_network,
        ],
        'suite' : 'network',
}

network_fuzz_template = fuzz_template + {
        'link_with' : [
                libshared,
                libsystemd_network,
        ],
}

executables += [
        network_test_template + {
                'sources' : files('test-acd.c'),
                'type' : 'manual',
        },
        network_test_template + {
                'sources' : files('test-dhcp-client.c'),
        },
        network_test_template + {
                'sources' : files('test-dhcp-option.c'),
        },
        network_test_template + {
                'sources' : files('test-dhcp-server.c'),
        },
        network_test_template + {
                'sources' : files('test-dhcp6-client.c'),
        },
        network_test_template + {
                'sources' : files('test-ipv4ll-manual.c'),
                'type' : 'manual',
        },
        network_test_template + {
                'sources' : files('test-ipv4ll.c'),
        },
        network_test_template + {
                'sources' : files('test-lldp-rx.c'),
        },
        network_test_template + {
                'sources' : files(
                        'test-ndisc-ra.c',
                        'icmp6-test-util.c',
                ),
                'extract' : files('icmp6-test-util.c'),
        },
        network_test_template + {
                'sources' : files('test-ndisc-rs.c'),
                'objects' : ['test-ndisc-ra'],
        },
        network_test_template + {
                'sources' : files('test-ndisc-send.c'),
                'type' : 'manual',
        },
        network_test_template + {
                'sources' : files('test-sd-dhcp-lease.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-dhcp-client.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-dhcp6-client.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-dhcp-server.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-dhcp-server-relay.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-lldp-rx.c'),
        },
        network_fuzz_template + {
                'sources' : files('fuzz-ndisc-rs.c'),
                'objects' : ['test-ndisc-ra'],
        },
]
