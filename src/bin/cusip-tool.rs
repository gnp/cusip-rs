//! This simple tool reads potential CUSIPs from stdin, one per line, and parses them. It will panic
//! if any fail to parse. This can be used as a simple bulk test of a file of purported CUSIPs to
//! ensure there are no malformed entries present. If you have a known-good file of valid CUSIPs, it
//! can be used to validate this crate considers them valid.
//!
//! As part of the `cusip` crate's initial validation, this tool was run on a file of 1,591,249
//! unique CUSIPs produced by processing a file mappin LEIs to ISINs obtained from GLEIF. The
//! [GLEIF file](https://www.gleif.org/en/lei-data/lei-mapping/download-isin-to-lei-relationship-files)
//! is very large (the version from 2021-02-09 was about 170MB). Here are a few example rows for US
//! ISINS:
//!
//! ```sh
//! grep ',US' ISIN_LEI_20210209.csv | head
//! S6XOOCT0IEG5ABCC6L87,US3137A3KN83
//! 254900EDYO1UYWLWP146,US12613N2027
//! 549300DRQQI75D2JP341,US05531GQN42
//! S6XOOCT0IEG5ABCC6L87,US31394GAX16
//! S6XOOCT0IEG5ABCC6L87,US3137ASGH19
//! G5GSEF7VJP5I7OUK5573,US06741RAP64
//! 549300LR1ZETOWYE9Z89,US084601MZ36
//! 8I5DZWZKVSZI1NUHU748,US46636JTK96
//! ANGGYXNX0JLX3X63JN86,US22546ESF24
//! 784F5XWPLTWKTBV3E584,US38143USC61
//! ```
//!
//! You can use a command like this to subset just the US ISINs and convert them to putative CUSIPs:
//!
//! ```sh
//! grep ',US' ISIN_LEI_20210209.csv \
//!   | sed -e 's/^.*,US//' \
//!   | sed -e 's/.$//' \
//!   | sort | uniq | gzip -9 \
//!   > cusips-us.txt.gz
//! ```
//!
//! This file was still about 4.2MB for the version tested.
//!
//! But, having produced it, it is now possible to run the file through this tool. From the source
//! directory of this crate, you can run:
//!
//! ```sh
//! gzcat cusips-us.txt.gz| cargo run cusip-tool
//! ```
//!
//! And, if all goes well, there will be no panic (and, no output either, currently).

use std::io;
use std::io::prelude::*;
use cusip;

#[doc(hidden)]
fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        cusip::parse(&line).unwrap();
    }
}
