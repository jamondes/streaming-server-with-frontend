# Start from the official node image for the app build
FROM node:latest AS build

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy all source files
COPY . .

# Build the app
RUN npm run build

# This container exposes port 3000 to the outside world
EXPOSE 3000

# Start the app
CMD ["npm", "start"]