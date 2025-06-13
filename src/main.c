#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_REQUEST_SIZE 4096
#define TIMEOUT 5

int read_request(char buffer[], int client_fd, int server_fd);
// int useRegex(char *textToCheck);
char *extract_path(const char *input);

int main() {
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  printf("Logs from your program will appear here!\n");

  int server_fd, client_addr_len;
  struct sockaddr_in client_addr;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEADDR failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(4221),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    printf("Listen failed: %s \n", strerror(errno));
    return 1;
  }

  printf("Waiting for a client to connect...\n");
  client_addr_len = sizeof(client_addr);

  int client_fd =
      accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
  printf("Client connected\n");
  printf("Client_fd: %d\n", client_fd);
  if (client_fd < 0) {
    printf("Accept failed: %s \n", strerror(errno));
    return 1;
  }

  char request_buffer[MAX_REQUEST_SIZE];

  read_request(request_buffer, client_fd, server_fd);
  printf("Received request:\n%s", request_buffer);
  printf("PRINTING PATH NOW\n");
  printf("%s\n", extract_path(request_buffer));

  char *response = "\0";
  printf("got past extract_path\n");
  printf("PATH: %s\n", extract_path(request_buffer));
  char* path = extract_path(request_buffer);
  if (path == NULL || strcmp(path, "") == 0) {
    printf("No valid path found in request\n");
    // Send 200 OK response
    response = "HTTP/1.1 200 OK\r\n\r\n";
    ssize_t bytes_sent = send(client_fd, response, strlen(response), 0);
  } else {
    printf("Valid path found: %s\n", path);
    response = "HTTP/1.1 404 Not Found\r\n\r\n";
    ssize_t bytes_sent = send(client_fd, response, strlen(response), 0);
  }

  close(server_fd);
  close(client_fd);

  return 0;
}

int read_request(char buffer[], int client_fd, int server_fd) {
  int total_read = 0;
  buffer[0] = '\0';  // Initialize buffer to an empty string

  while (total_read <= MAX_REQUEST_SIZE - 1) {
    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(client_fd, &read_fds);

    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;

    int indication = select(client_fd + 1, &read_fds, NULL, NULL, &timeout);
    // printf("Indication from select: %d\n", indication);
    if (indication == -1) {
      printf("Select failed: %s\n", strerror(errno));
      close(client_fd);
      close(server_fd);
      return 1;
    } else if (indication == 0) {
      printf("Timeout occured, no data received within %d seconds.\n", TIMEOUT);
      close(client_fd);
      close(server_fd);
      return 1;
    }

    ssize_t bytes_recvd = recv(client_fd, buffer + total_read,
                               MAX_REQUEST_SIZE - 1 - total_read, 0);
    if (bytes_recvd < 0) {
      printf("Receive failed: %s \n", strerror(errno));
      close(client_fd);
      close(server_fd);
      return 1;
    }

    total_read += bytes_recvd;
    buffer[total_read] = '\0';

    // printf("Bytes received: %zd\n", bytes_recvd);
    // printf("Total bytes read: %d\n", total_read);
    // printf("Buffer content: %s\n", buffer);

    if (strstr(buffer, "\r\n\r\n")) {
      printf("End of request\n");
      break;
    }

    if (total_read >= MAX_REQUEST_SIZE - 1) {
      printf("Request too large, exceeding maximum size of %d bytes.\n",
             MAX_REQUEST_SIZE);
      // Send 413 status code
      close(client_fd);
      close(server_fd);
      return 1;
    }
  }
}

// int useRegex(char *textToCheck) {
//   regex_t compiledRegex;
//   int reti;
//   int actualReturnValue = -1;
//   char messageBuffer[100];

//   /* Compile regular expression */
//   reti = regcomp(&compiledRegex, "GET /[^[:space:]]*", REG_EXTENDED |
//   REG_ICASE); if (reti) {
//     fprintf(stderr, "Could not compile regex\n");
//     return -2;
//   }

//   /* Execute compiled regular expression */
//   reti = regexec(&compiledRegex, textToCheck, 0, NULL, 0);
//   if (!reti) {
//     puts("Match");
//     actualReturnValue = 0;
//   } else if (reti == REG_NOMATCH) {
//     puts("No match");
//     actualReturnValue = 1;
//   } else {
//     regerror(reti, &compiledRegex, messageBuffer, sizeof(messageBuffer));
//     fprintf(stderr, "Regex match failed: %s\n", messageBuffer);
//     actualReturnValue = -3;
//   }

//   /* Free memory allocated to the pattern buffer by regcomp() */
//   regfree(&compiledRegex);
//   return actualReturnValue;
// }

char *extract_path(const char *input) {
  printf("READING PATH\n");
  regex_t regex;
  regmatch_t pmatch[2];
  const char *pattern = "^GET /([^[:space:]]*)";
  char *result = NULL;
  printf("Input: %s\n", input);

  if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
    printf("Could not compile regex\n");
    return NULL;  // regex failed to compile
  }

  if (regexec(&regex, input, 2, pmatch, 0) == 0) {
    printf("Regex match found\n");
    int start = pmatch[1].rm_so;
    int end = pmatch[1].rm_eo;
    int len = end - start;

    // If there's nothing after the slash, return NULL
    if (len == 0) {
      printf("No path found after slash\n");
      regfree(&regex);
      printf("returning NULL\n");
      return "HELKJALSKJDAOSIJDAOS";
    }

    // Allocate memory (+1 for null terminator)
    result = malloc(len + 1);
    if (result == NULL) {
      perror("malloc failed");
      exit(1);
    }

    // Copy and null-terminate
    strncpy(result, input + start, len);
    result[len] = '\0';
  }

  regfree(&regex);
  printf("returning result\n");
  return result;
}