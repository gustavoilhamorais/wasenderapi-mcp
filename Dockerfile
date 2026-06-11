FROM node:24-alpine
WORKDIR /app
# Zero runtime deps: only package.json + source are needed.
COPY package.json ./
COPY src ./src
ENV NODE_ENV=production
# Run unprivileged as the image's built-in `node` user (uid 1000). The SQLite
# DB lives under /data (a mounted volume); create it owned by node so the
# process can write. If you bind-mount an existing host directory onto /data,
# make it writable by uid 1000 first, e.g. `sudo chown -R 1000:1000 ./data`.
RUN mkdir -p /data && chown -R node:node /data
USER node
EXPOSE 8080
CMD ["node", "src/server.js"]
