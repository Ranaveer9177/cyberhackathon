FROM node:latest

WORKDIR /app

ENV DATABASE_URL=postgresql://admin:password123@db:5432/production
ENV API_SECRET=hardcoded-secret-in-dockerfile
ENV NODE_ENV=production

COPY . .

RUN npm install

EXPOSE 3000
EXPOSE 8080
EXPOSE 5432

CMD ["node", "server.js"]
