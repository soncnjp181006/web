# VulnShop backend container: nginx gateway (port 10000) -> node (127.0.0.1:4000)
FROM node:20-alpine

# nginx as the API gateway inside the container (Render $PORT=10000)
RUN apk add --no-cache nginx

WORKDIR /app

COPY package*.json ./
RUN npm install --no-audit --no-fund --omit=dev

COPY . .

RUN mkdir -p /app/uploads && rm -f /etc/nginx/http.d/default.conf
COPY nginx/app.conf /etc/nginx/http.d/app.conf

# Render web services must bind 0.0.0.0:$PORT (default 10000)
ENV PORT=10000 \
    INTERNAL_PORT=4000 \
    NODE_ENV=production

EXPOSE 10000

CMD ["sh", "-c", "nginx && exec node server.js"]
