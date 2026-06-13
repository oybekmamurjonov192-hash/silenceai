FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency definition
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy application files
COPY server.js database.js ai_engine.js agent.js auth.js telegram.js index.html login.html app.js style.css ./

# Expose server port
EXPOSE 3000

# Set environment
ENV NODE_ENV=production
ENV PORT=3000

# Command to run backend
CMD ["node", "server.js"]
