# Reproduce the unlinked sum-proof case on top of the official verifier image.
# Build the base first from the parent directory (see README.md).
ARG BASE_IMAGE=feddeg-official-bugs
FROM ${BASE_IMAGE}

COPY unlinked_sum.csv /tmp/case.csv
RUN mkdir -p /app/files \
 && python3 -c "import zipfile; z=zipfile.ZipFile('/app/files/4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u.zip','w',zipfile.ZIP_DEFLATED); z.write('/tmp/case.csv', arcname='4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u.csv'); z.close()"

ENTRYPOINT ["node", "/app/dist/index.js"]
CMD ["validate", "4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u", "--no-tx-sig", "--verbose"]
