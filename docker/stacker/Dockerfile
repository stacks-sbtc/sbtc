FROM node:20-bookworm AS builder

RUN apt-get update && apt-get install -y curl gettext-base jq
RUN npm install -g pnpm@10

WORKDIR /root
COPY ./stacking/package.json /root/
# We don't have access to the root lockfile so we can't use --frozen-lockfile
RUN pnpm install

COPY ./stacking/stacking.ts ./stacking/common.ts ./stacking/monitor.ts ./stacking/tx-broadcaster.ts /root/

CMD ["npx", "tsx", "/root/stacking.ts"]
