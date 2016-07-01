echo "Installing recommended fonts for TeX"
mount -o remount,rw /
apt-get install texlive-fonts-recommended
#tlmgr option repository ftp://tug.org/historic/systems/texlive/2015/tlnet-final 
#tlmgr install collection-fontsrecommended
