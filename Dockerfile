# HinataAuth - OAuth 2.0 Authorization Server
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files
COPY HinataAuth.csproj ./
RUN dotnet restore

COPY . ./
RUN dotnet publish -c Release -o /app/publish --no-restore HinataAuth.csproj

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

# Install SSL certificates if needed (for production use)
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     ca-certificates \
#     && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .

# Expose the default port
EXPOSE 5999

# Set the entry point
ENTRYPOINT ["dotnet", "HinataAuth.dll"]
