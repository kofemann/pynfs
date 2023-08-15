FROM almalinux:9-minimal

RUN microdnf install -y git-core krb5-devel python3-devel python3-gssapi python3-ply tar
RUN git clone --depth=1 git://git.linux-nfs.org/projects/bfields/pynfs.git
RUN cd pynfs && python3 setup.py build

COPY run-nfs4.0.sh /run-nfs4.0.sh
COPY run-nfs4.1.sh /run-nfs4.1.sh

RUN chmod +x /run-nfs4.0.sh /run-nfs4.1.sh

RUN microdnf clean all && rm -rf /var/cache/yum /var/lib/dnf /var/lib/rpm

