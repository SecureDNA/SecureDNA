// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::shared::util::read_lines;
use std::collections::HashMap;
use std::fs;
use std::process::Command;

pub fn start_nmon(file_name: &str) -> String {
    let output = Command::new("nmon")
        .args(["-p", "-F", file_name, "-s 1", "-c 999999"])
        .output()
        .expect("Failed to start NMON");

    let mut pid = String::from_utf8(output.stdout).unwrap();
    pid.pop().unwrap().to_string();
    pid
}

pub fn stop_nmon(pid: &str) {
    Command::new("kill")
        .args(["-SIGTERM", pid])
        .output()
        .expect("Failed to stop NMON");
}

/* Rewrite NMON files to sync the timestamps and overlay the metrics */

pub fn process_nmon(baseline_file: String, new_file: String) {
    let mut baseline_timestamps = Vec::new();
    let mut new_with_timestamps: String = String::new();
    let nmon_labels = HashMap::from([
        ("MEM,Memory MB", "MEM,Memory MB ip-172-31-67-250,memtotal-2,hightotal-2,\
                                lowtotal-2,swaptotal,memfree-2,highfree-2,lowfree-2,swapfree,memshared-2,\
                                cached-2,active-2,bigfree-2,buffers-2,swapcached-2,inactive-2"),
        ("PROC,Processes ", "PROC,Processes ip-172-31-67-250,Runnable2,Blocked2,pswitch-2,syscall-2,read-2,write-2,fork-2,exec-2,sem-2,msg-2"),
        ("NETPACKET,Network Packets ", "NETPACKET,Network Packets ip-172-31-67-250,lo-read/s-2,ens5-read/s-2,br-cef4da2c2edd-read/s-2,docker0-read/s-2,\
                                        lo-write/s-2,ens5-write/s-2,br-cef4da2c2edd-write/s-2,docker0-write/s-2"),
        ("DISKBUSY,Disk %Busy", "DISKBUSY,Disk %Busy ip-172-31-67-250,loop0-2,loop1-2,loop2-2,loop3-2,loop4-2,loop5-2,loop6-2,loop7-2,nvme0n1-2,\
                                        nvme0n1p1-2,nvme0n1p14-2,nvme0n1p15-2,loop8-2,loop9-2,loop10-2"),
        ("DISKREAD,Disk Read ", "DISKREAD,Disk Read KB/s ip-172-31-67-250,loop0-2,loop1-2,loop2-2,loop3-2,loop4-2,loop5-2,loop6-2,loop7-2,nvme0n1-2,\
                                        nvme0n1p1-2,nvme0n1p14-2,nvme0n1p15-2,loop8-2,loop9-2,loop10-2"),
        ("DISKWRITE,Disk Write KB/s ", "DISKWRITE,Disk Write KB/s ip-172-31-67-250,loop0-2,loop1-2,loop2-2,loop3-2,loop4-2,loop5-2,loop6-2,loop7-2,\
                                        nvme0n1-2,nvme0n1p1-2,nvme0n1p14-2,nvme0n1p15-2,loop8-2,loop9-2,loop10-2"),
        ("DISKXFER,Disk transfers per second ", "DISKXFER,Disk transfers per second ip-172-31-67-250,loop0-2,loop1-2,loop2-2,loop3-2,loop4-2,loop5-2,\
                                        loop6-2,loop7-2,nvme0n1-2,nvme0n1p1-2,nvme0n1p14-2,nvme0n1p15-2,loop8-2,loop9-2,loop10-2"),
        ("DISKBSIZE,Disk Block Size ", "DISKBSIZE,Disk Block Size ip-172-31-67-250,loop0-2,loop1-2,loop2-2,loop3-2,loop4-2,loop5-2,loop6-2,loop7-2,\
                                        nvme0n1-2,nvme0n1p1-2,nvme0n1p14-2,nvme0n1p15-2,loop8-2,loop9-2,loop10-2"),
        ("VM,Paging and Virtual Memory", "VM,Paging and Virtual Memory,nr_dirty-2,nr_writeback-2,nr_unstable-2,nr_page_table_pages-2,nr_mapped-2,\
                                        nr_slab_reclaimable-2,pgpgin-2,pgpgout-2,pswpin-2,pswpout-2,pgfree-2,pgactivate-2,pgdeactivate-2,pgfault-2,\
                                        pgmajfault-2,pginodesteal-2,slabs_scanned-2,kswapd_steal-2,kswapd_inodesteal-2,pageoutrun-2,allocstall-2,\
                                        pgrotated-2,pgalloc_high-2,pgalloc_normal-2,pgalloc_dma-2,pgrefill_high,pgrefill_normal-2,pgrefill_dma-2,\
                                        pgsteal_high-2,pgsteal_normal-2,pgsteal_dma-2,pgscan_kswapd_high-2,pgscan_kswapd_normal-2,pgscan_kswapd_dma-2,\
                                        pgscan_direct_high-2,pgscan_direct_normal-2,pgscan_direct_dma-2")
    ]);

    // Load the timestamps for the baseline file

    if let Ok(lines) = read_lines(baseline_file) {
        for header in lines.map_while(Result::ok) {
            if header.starts_with("ZZZZ") {
                baseline_timestamps.push(header);
            }
        }
    }

    println!("Building new NMON file with synced timestamps...");
    let mut counter = 0;
    if let Ok(lines) = read_lines(&new_file) {
        for row in lines.map_while(Result::ok) {
            let mut h = false;
            for (key, value) in &nmon_labels {
                if row.starts_with(key) {
                    new_with_timestamps.push_str(format!("{value}\n").as_str());
                    h = true;
                }
            }
            if h {
                continue;
            }

            if row.starts_with("ZZZZ") {
                // insert the new header
                if counter < baseline_timestamps.len() {
                    new_with_timestamps
                        .push_str(format!("{}\n", baseline_timestamps[counter]).as_str());
                }
                counter += 1;
            } else {
                // replace the original
                new_with_timestamps.push_str(format!("{row}\n").as_str());
            }
        }
    }
    fs::write(new_file, new_with_timestamps).expect("Unable to write file");
}
