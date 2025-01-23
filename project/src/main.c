#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <pthread.h>

// Process data structure

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct process
{
  pid_t pid;
  pid_t ppid;
};

int process_count = 0;
int process_array_block_size = 25;
struct process *processes = NULL;

int compare_processes(const void *process_one, const void *process_two)
{
  struct process process_one_value = *((struct process *)process_one);
  struct process process_two_value = *((struct process *)process_two);
  if (process_one_value.ppid == process_two_value.ppid)
  {
    if (process_one_value.pid == process_two_value.pid)
      return 0;
    else
      return process_one_value.pid < process_two_value.pid ? -1 : 1;
  }
  else
    return process_one_value.ppid < process_two_value.ppid ? -1 : 1;
}

int refresh_processes()
{
  DIR *dir = opendir("/proc");
  if (dir == NULL)
    return -ENOENT;

  if (process_count != 0)
  {
    free(processes);
    processes = NULL;
  }
  process_count = 0;

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
    if (entry->d_type == DT_DIR && isdigit(entry->d_name[0]))
    {
      if (process_count % process_array_block_size == 0)
      {
        if (process_count)
          processes = (struct process *)realloc(processes, (process_count + process_array_block_size + 1) * sizeof(struct process));
        else
          processes = (struct process *)malloc((process_array_block_size + 1) * sizeof(struct process));
      }

      char *stat_file_path;
      stat_file_path = (char *)malloc((15 + strlen(entry->d_name)) * sizeof(char));
      sprintf(stat_file_path, "/proc/%s/stat", entry->d_name);

      FILE *stat_file = fopen(stat_file_path, "r");

      char status;
      char *name;
      int pid, ppid;

      name = (char *)malloc(16 * sizeof(char));
      fscanf(stat_file, "%d %s %c %d", &pid, name, &status, &ppid);
      free(name);

      fclose(stat_file);
      free(stat_file_path);

      processes[process_count].pid = pid;
      processes[process_count].ppid = ppid;

      process_count++;
    }

  closedir(dir);

  qsort(processes, process_count, sizeof(struct process *), compare_processes);

  printf("[refresh] - Finished refresh\n");

  return 1;
}

void print_processes_information()
{
  for (int process_index = 0; process_index < process_count; process_index++)
    printf("PPID %d - PID %d\n", processes[process_index].ppid, processes[process_index].pid);
}

int get_process_index(pid_t pid, pid_t ppid)
{
  struct process searched_process;
  searched_process.ppid = ppid;
  searched_process.pid = pid;

  int left = -1, right = process_count;
  int result_candidate_index = -1;

  while (right - left > 1)
  {
    int middle = left + (right - left) / 2;
    if (compare_processes(&processes[middle], &searched_process) != 1)
    {
      left = middle;
      result_candidate_index = middle;
    }
    else
      right = middle;
  }

  if (result_candidate_index == -1)
    return -1;
  else if (compare_processes(&processes[result_candidate_index], &searched_process) == 0)
    return result_candidate_index;
  else
    return -1;
}

int get_ppid_first_index(pid_t ppid)
{
  int left = -1, right = process_count;
  int result_candidate_index = -1;

  while (right - left > 1)
  {
    int middle = left + (right - left) / 2;
    if (processes[middle].ppid < ppid)
      left = middle;
    else
    {
      right = middle;
      result_candidate_index = middle;
    }
  }

  if (result_candidate_index == -1)
    return -1;
  else if (processes[result_candidate_index].ppid == ppid)
    return result_candidate_index;
  else
    return -1;
}

// Path utilities

int pid_char_length(pid_t pid)
{
  int char_count = 0;
  do
  {
    char_count++;
    pid /= 10;
  } while (pid);
  return char_count;
}

bool is_status_file(const char *path)
{
  size_t path_len = strlen(path);
  return (path_len > 6 && strcmp(path + path_len - 6, "status") == 0);
}

pid_t get_pid_in_path(const char *path, int offset)
{
  pid_t parent_pid = 0;
  int p10 = 1, pos = strlen(path) - 1 - offset;
  while (pos > 0 && path[pos] != '/')
  {
    parent_pid += (path[pos] - '0') * p10;
    p10 *= 10;
    --pos;
  }
  return parent_pid;
}

// FUSE

static int pseudofs_getattr(const char *path, struct stat *st)
{
  printf("[getattr] - %s\n", path);

  st->st_uid = getuid();
  st->st_gid = getgid();
  st->st_atime = time(NULL);
  st->st_mtime = time(NULL);

  // Check if file path ends with "status"
  if (is_status_file(path))
  {
    st->st_mode = S_IFREG | 0644;
    st->st_nlink = 1;
    st->st_size = 1024;
  }
  else
  {
    pid_t pid = get_pid_in_path(path, 0);
    pid_t ppid = get_pid_in_path(path, pid_char_length(pid) + 1);

    pthread_mutex_lock(&lock);
    int existing_process_index = get_process_index(pid, ppid);
    pthread_mutex_unlock(&lock);

    // Allow access to folder only if process exists
    if (existing_process_index != -1 || (pid == 0 && ppid == 0))
    {
      st->st_mode = S_IFDIR | 0755;
      st->st_nlink = 2;
    }
    else
      return -ENOENT;
  }

  return 0;
}

static int pseudofs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
  printf("[readdir] - %s\n", path);

  filler(buffer, ".", NULL, 0, FUSE_FILL_DIR_PLUS);  // Current Directory
  filler(buffer, "..", NULL, 0, FUSE_FILL_DIR_PLUS); // Parent Directory

  pid_t parent_pid = get_pid_in_path(path, 0);

  pthread_mutex_lock(&lock);
  int process_index = get_ppid_first_index(parent_pid);

  while (process_index <= process_count)
  {
    if (processes[process_index].ppid != parent_pid)
      break;

    char child_pid[10];
    sprintf(child_pid, "%d", processes[process_index].pid);
    filler(buffer, child_pid, NULL, 0, FUSE_FILL_DIR_PLUS);

    process_index++;
  }
  pthread_mutex_unlock(&lock);

  if (parent_pid != 0)
    filler(buffer, "status", NULL, 0, FUSE_FILL_DIR_PLUS);

  return 0;
}

static int pseudofs_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
  printf("[read] - %s, %lu, %lu\n", path, offset, size);

  if (is_status_file(path))
  {
    pid_t pid = get_pid_in_path(path, 7);

    char status_file_path[25];
    sprintf(status_file_path, "/proc/%d/status", pid);

    FILE *status_file = fopen(status_file_path, "r");
    if (status_file == NULL)
    {
      perror("Can not find information on selected process!");
      return -ENOENT;
    }

    char *file_data, *line = NULL;
    size_t file_length = 0, line_length = 0;

    while (getline(&line, &line_length, status_file) != EOF)
    {
      if (file_length == 0)
      {
        file_data = (char *)malloc((line_length + 1) * sizeof(char));
        file_data[0] = '\0';
      }
      else
        file_data = (char *)realloc(file_data, (file_length + line_length + 1) * sizeof(char));

      file_length += line_length;
      strcat(file_data, line);
      file_data[file_length] = '\n';
    }

    fclose(status_file);

    if ((size_t)offset >= file_length)
      return 0;

    memcpy(buffer, file_data + offset, size);
    return strlen(file_data - offset);
  }
  else
    return -1;
}

static struct fuse_operations operations = {
    .getattr = pseudofs_getattr,
    .readdir = pseudofs_readdir,
    .read = pseudofs_read,
};

void refresh_function(void *args)
{
  while (1)
  {
    pthread_mutex_lock(&lock);
    refresh_processes();
    pthread_mutex_unlock(&lock);

    sleep(5);
  }
}

int main(int argc, char *argv[])
{
  pthread_t thread;
  if (pthread_create(&thread, NULL, refresh_function, NULL))
  {
    perror("Could not create process refresh thread!");
    return errno;
  }

  sleep(1);
  return fuse_main(argc, argv, &operations, NULL);
}