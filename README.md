# tls_cert_att

# install

    pacman -S certificate-ripper-bin python-jwcrypto jdk17-openjdk maven openssl

# prepare attester

    ./gen_attester_cert.sh

# prepare tls certs

    perl get_certs.pl
    find . -name 'data/*.txt' -exec grep -H Issuer {} \;

# prepare crtatt

    ./gen_crtatt.py
    ./verify_crtatt.py

# ctca

    cd ctca
    mvn package

    ./ctca_benchmark.pl
