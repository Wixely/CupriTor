# CupriTor host — containerized sidecar. Expose a local/backend app over Tor, clearnet, or both.
# The build needs the CupriCurve package resolvable (GitHub Packages with a read:packages PAT, or a local
# feed). Provide a NuGet.config with the source, or mount one, before building.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/CupriTor.Host/CupriTor.Host.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Persist the onion identity in a volume so the .onion address is stable across restarts.
VOLUME /data
ENV CupriTor__Onion__IdentityFile=/data/onion.key
# Sensible container default: onion only, backend reachable on the container network.
ENV CupriTor__Mode=TorOnly
ENV CupriTor__Backend=host.docker.internal:8080

ENTRYPOINT ["dotnet", "cupritor-host.dll"]
