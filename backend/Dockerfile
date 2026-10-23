FROM mcr.microsoft.com/playwright:v1.52.0-noble

WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY sandbox-server.mjs .

ENV NODE_ENV=production
ENV SANDBOX_PORT=4892
ENV SANDBOX_TIMEOUT_MS=15000

EXPOSE 4892
USER pwuser
CMD ["node", "sandbox-server.mjs"]
