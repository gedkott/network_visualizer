Fun project I did to write Rust code, use pcap, and learn a little bit about lower level networking.
The executable generates a dot file that can then be used with dot CLI to produce a visual graph.

Generate dot file:
1. Set up Rust, clone this repo
2. Somehow setup pcap lib and other needed system libraries depending on how your OS/Arch works
3. `cargo build`
4. `sudo ./target/debug/networking` - On my setup, I had to do it this way because some aspects of using PCAP (I don't know which ones precisely) require root access.

Visualizing dot file:
1. get the dot CLI somehow
2. `dot -Tsvg my_network.dot -o outfile.svg`
3. use a browser or any SVG renderer to open the outfile.svg file and check it out