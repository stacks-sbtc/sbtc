curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
~/.cargo/bin/cargo doc --no-deps
cp ./.doc/index.html ./target/doc/

# apt-get install texlive
# apt-get install texlive-latex-extra
# pdflatex ./wsts.tex
# pdflatex ./wsts.tex

# cp ./wsts.pdf ./target/doc/
