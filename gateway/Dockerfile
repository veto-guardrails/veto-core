FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/veto-gateway .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/veto-gateway /veto-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/veto-gateway"]
