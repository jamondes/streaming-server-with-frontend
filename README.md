# My Project

This is a simple project that demonstrates a web application with backend and frontend components, powered by Docker and Docker Compose.

## Prerequisites

Make sure you have the following tools installed on your machine:
- Docker: [Install Docker](https://docs.docker.com/get-docker/)
- Docker Compose: [Install Docker Compose](https://docs.docker.com/compose/install/)

## Getting Started

To run the project locally, follow these steps:

1. Clone the repository:
   ```
   git clone https://github.com/jamondes/streaming-server-with-frontend
   ```

2. Navigate to the project directory:
   ```
   cd streaming-server-with-frontend
   ```

3. Build and start the Docker containers using Docker Compose:
   ```
   docker-compose up --build
   ```

   The `--build` flag ensures that the images are rebuilt if any changes are detected in the Dockerfiles or the source code.

4. Once the containers are up and running, you can access the application in your web browser:
   - Backend: [http://localhost:8080](http://localhost:8080)
   - Frontend: [http://localhost:3000](http://localhost:3000)

5. Press `Ctrl + C` in the terminal to stop the containers when you're done.

## Folder Structure

The project has the following structure:
- `backend/`: Contains the backend code and Dockerfile.
- `frontend/`: Contains the frontend code and Dockerfile.
- `docker-compose.yml`: Defines the services and configurations for Docker Compose.

## Additional Information

- The backend service is built with Go and uses a PostgreSQL database for user authentication and streaming functionality.
- The frontend service is a React application that interacts with the backend APIs.
- The project includes a `docker-compose.yml` file that orchestrates the deployment of the services using Docker Compose.
- The project is designed to be self-contained and can be run with a single command using Docker Compose.

Feel free to explore and modify the code to suit your needs.

If you have any questions or need further assistance, please let us know.

Enjoy your project!
