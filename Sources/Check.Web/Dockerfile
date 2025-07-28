# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

# Stage 1: Base image for runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
USER app
WORKDIR /app
EXPOSE 5248
EXPOSE 7208

# Install dependencies for Xray or other tools (if needed)
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Build the service project
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Sources/Check.Web/Check.Web.csproj", "Sources/Check.Web/"]
COPY ["Sources/Check.Core/Check.Core.csproj", "Sources/Check.Core/"]
RUN dotnet restore "./Sources/Check.Web/Check.Web.csproj"
COPY Sources/ Sources/
WORKDIR "/src/Sources/Check.Web"
RUN dotnet build "./Check.Web.csproj" -c $BUILD_CONFIGURATION -o /app/build

# Stage 3: Publish the service project
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Check.Web.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# Stage 4: Final image for production
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Copy additional configuration files or tools (e.g., Xray binary) if needed
# Example: COPY ./tools/xray /app/xray
# Ensure Xray is executable: RUN chmod +x /app/xray

# Set environment variables for port configuration
ENV ASPNETCORE_URLS="https://+:7208;http://+:5248"
ENV ASPNETCORE_ENVIRONMENT=Development

# Copy appsettings.json and other configuration files
COPY Sources/Check.Web/appsettings*.json /app/

ENTRYPOINT ["dotnet", "Check.Web.dll"]