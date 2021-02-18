#! /usr/bin/python3
# coding=utf-8
def create_list_from_search_file(users_file_list):
  users_list = set()
  with open(users_file_list, encoding='utf-8', errors='ignore') as users_file:
      for user in users_file.readlines():
          try:
              user = user.strip()
              users_list.add(user)
          except:
              pass
  return list(users_list)

def read_and_check_in_file(pass_file, users_list):
    users = {}
    with open(pass_file, encoding='utf-8', errors='ignore') as dump_file:
        for user in users_list:
            dump_file.seek(0, 0)
            user_exist = False
            for line in dump_file:
                if user in line:
                    user_exist = True
                    users[user] = line.split(',')[1].strip()
                    break
            if not user_exist:
                users[user] = 'X'
            print(users[user])
    with open('results.txt', 'r') as file:
        file.write(users)

users_list = create_list_from_search_file(users_file_list='users_list.txt')
read_and_check_in_file(pass_file='/var/test/all_files/all_data.done', users_list=users_list)