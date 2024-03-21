import io
import os

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
import psycopg2
from psycopg2.sql import Identifier, SQL, Literal

import pandas as pd

# Create your views here.
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest, FileResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

ADMIN_GROUPS = ['admin']
EXPORT_FORMATS = ['xlsx', 'csv', 'tex']


# Функция для обновления строки
def update_row_in_table(conn, tablename, row_data):
    # Ваша логика обновления строки в таблице
    # Пример обновления одного поля:
    # cursor.execute(sql.SQL("UPDATE {} SET column_name = %s WHERE id = %s").format(sql.Identifier(tablename)), [row_data['column_value'], row_data['row_id']])
    cursor = conn.cursor()
    header_prim_key = row_data.pop('header_primary_key')
    row_prim_key = row_data.pop('row_primary_key')
    keys = ', '.join([f"{key} = %s" for key in row_data.keys()])
    values = tuple(row_data.values())
    cursor.execute(f"UPDATE {tablename} SET {keys} WHERE {header_prim_key} = %s", values + (row_prim_key,))
    cursor.close()


# Функция для добавления строки
def add_row(conn, tablename, row_data):
    # Ваша логика обновления строки в таблице
    # Пример обновления одного поля:
    # cursor.execute(sql.SQL("UPDATE {} SET column_name = %s WHERE id = %s").format(sql.Identifier(tablename)), [row_data['column_value'], row_data['row_id']])
    cursor = conn.cursor()
    keys = ', '.join(row_data.keys())
    values = tuple(row_data.values())
    cursor.execute(f"INSERT INTO {tablename} VALUES ({('%s, ' * len(values))[:-2]})", values)
    cursor.close()


# Функция для удаления строки
def delete_row_from_table(conn, tablename, row_data):
    # Ваша логика удаления строки из таблицы
    # Пример удаления строки:
    # cursor.execute(sql.SQL("DELETE FROM {} WHERE id = %s").format(sql.Identifier(tablename)), [row_id])
    cursor = conn.cursor()
    header_prim_key = row_data.pop('header_primary_key')
    row_prim_key = row_data.pop('row_primary_key')
    cursor.execute(f"DELETE FROM {tablename}  WHERE {header_prim_key} = %s", (row_prim_key,))
    cursor.close()


@require_POST
@csrf_exempt
def update_table_row(request):
    if (not request.user.is_authenticated and len(request.user.groups.all()) > 0
            and request.user.groups.all()[0] in ADMIN_GROUPS):
        return JsonResponse({'status': 'error', 'message': 'Authentication required'}, status=403)

    # Получаем данные из запроса
    tablename = request.POST.get('tablename')
    row_id = request.POST.get('row_id')
    is_delete = request.POST.get('is_delete', 'false') == 'true'
    is_add = request.POST.get('is_add', 'false') == 'true'
    data = request.POST.dict()
    data.pop('tablename', None)
    data.pop('row_id', None)
    data.pop('is_delete', None)
    data.pop('is_add', None)

    try:
        # Установление соединения с базой данных
        conn = psycopg2.connect(
            host=request.session.get('host_url'),
            dbname=request.session.get('db_name'),
            user=request.session.get('username'),
            password=request.session.get('password')
        )
        cursor = conn.cursor()

        # Вызов функции обновления или удаления в зависимости от запроса
        if is_delete:
            delete_row_from_table(conn, tablename, data)
        elif is_add:
            add_row(conn, tablename, data)
        else:
            update_row_in_table(conn, tablename, data)

        conn.commit()  # Подтверждение транзакции

        return JsonResponse({'status': 'success', 'message': 'Operation successful'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    finally:
        if conn:
            conn.close()


def export_table(request, tablename, export_format):
    if export_format not in EXPORT_FORMATS:
        return HttpResponseBadRequest('File format not supported')
    if not request.user.is_authenticated:
        return redirect('auth')
    if not ('host_url' in request.session and
            'db_name' in request.session and
            'username' in request.session and
            'password' in request.session):
        return redirect('settings')
    cursor = None
    conn = None
    try:
        conn = psycopg2.connect(host=request.session['host_url'], dbname=request.session['db_name'],
                                user=request.session['username'], password=request.session['password'])
        cursor = conn.cursor()
        cursor.execute(SQL("SELECT * FROM {}").format(Identifier(tablename)))
        temp_content = [table for table in cursor]
        table_contents = [i[1:] for i in temp_content]
        table_indexes = [i[0] for i in temp_content]
        table_headers = [table.name for table in cursor.description]

        table = pd.DataFrame(data=table_contents, columns=table_headers[1:], index=table_indexes)

        sw = {'csv': (table.to_csv, io.BytesIO),
              'xlsx': (table.to_excel, io.BytesIO),
              'tex': (table.to_latex, io.StringIO)}
        assert set(sw.keys()) == set(EXPORT_FORMATS), 'not all formats initialized'

        output = sw[export_format][1]()
        sw[export_format][0](output)

        response = HttpResponse(output.getvalue())
        response['Content-Disposition'] = f'attachment; filename="{tablename}.{export_format}"'
        return response
    except Exception as ex:
        return HttpResponseBadRequest(f'Error {ex}')
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


def render_main_page(request, tablename=None, viewname=None, triggername = None, functionname = None):
    if not request.user.is_authenticated:
        return redirect('auth')
    if not ('host_url' in request.session and
            'db_name' in request.session and
            'username' in request.session and
            'password' in request.session):
        return redirect('settings')

    # initialization
    cursor = None
    table_list = []
    views_list = []
    trigger_list = []
    function_list = []
    conn = None

    user_group = request.user.groups.all()[0].name if len(request.user.groups.all()) > 0 else ''
    try:
        conn = psycopg2.connect(host=request.session['host_url'], dbname=request.session['db_name'],
                                user=request.session['username'], password=request.session['password'])
        cursor = conn.cursor()
        cursor.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'")

        table_list = [table[0] for table in cursor]
        cursor.execute("select table_name from INFORMATION_SCHEMA.views where table_schema = 'public'")
        views_list = [view[0] for view in cursor]
        cursor.execute("select trigger_name from INFORMATION_SCHEMA.triggers")
        trigger_list = [trigger[0] for trigger in cursor]

        cursor.execute("select routine_name from information_schema.routines where routine_type = 'FUNCTION' and routine_schema = 'public'")
        function_list = [function[0] for function in cursor]
        print(len(function_list))
        table_contents = None
        table_headers = None
        definition = None
        if tablename is not None:
            # Using a parameterized query for security
            query = SQL("SELECT * FROM {}").format(Identifier(tablename))
            cursor.execute(query)
            table_contents = [row for row in cursor]
            table_headers = [col.name for col in cursor.description]

        elif viewname is not None:
            # Directly query the view
            query = SQL("SELECT * FROM {}").format(Identifier(viewname))
            cursor.execute(query)
            table_contents = [row for row in cursor]
            table_headers = [col.name for col in cursor.description]
        elif triggername is not None:
            # Получение текста триггера по его имени
            query = SQL("SELECT action_statement FROM INFORMATION_SCHEMA.triggers WHERE trigger_name = %s")
            cursor.execute(query, (triggername,))
            definition = cursor.fetchone()[0]
        elif functionname is not None:
            # Directly query the view
            query = SQL("SELECT routine_definition FROM information_schema.routines WHERE routine_type = 'FUNCTION' AND routine_schema = 'public' AND routine_name = %s;")

            cursor.execute(query, (functionname,))
            definition = cursor.fetchone()[0]




    except Exception as ex:
        return render(request, 'index.html',
                      {'username': request.user.username, 'error': ex, 'table_list': table_list,
                       'view_list': views_list, 'trigger_list': trigger_list,'function_list': function_list,
                       'group_name': user_group, 'db_name': 'oopsie daisies'})
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()

    return render(request, 'index.html',
                  {'username': request.user.username, 'db_name': request.session['db_name'], 'table_list': table_list,
                   'view_list': views_list, 'trigger_list': trigger_list, 'fucntion_list': function_list,
                   'table_contents': table_contents, 'table_headers': table_headers, 'tablename': tablename, 'triggername': triggername, 'definition': definition,
                   'viewname': viewname, 'funtionname': functionname,
                   'group_name': user_group,
                   'is_admin': user_group in ADMIN_GROUPS})


#
def render_settings_page(request):
    if request.method == 'POST':
        host_url = request.POST["host"]
        db_name = request.POST["database"]
        username = request.POST["username"]
        password = request.POST["password"]
        request.session['host_url'] = host_url
        request.session['db_name'] = db_name
        request.session['username'] = username
        request.session['password'] = password

        try:
            conn = psycopg2.connect(dbname=db_name, user=username, password=password, host=host_url)
            conn.close()
        except Exception as ex:
            return render(request, 'settings.html', {'username': request.user.username, 'error': ex, 'db_host_url': '',
                                                     'db_name': '', 'db_username': '', 'db_password': ''})

        return render(request, 'settings.html', {'username': request.user.username, 'status': 'Successfully connected',
                                                 'db_host_url': request.session['host_url'],
                                                 'db_name': request.session['db_name'],
                                                 'db_username': request.session['username'],
                                                 'db_password': request.session['password']})
    else:
        if 'host_url' in request.session and \
                'db_name' in request.session and \
                'username' in request.session and \
                'password' in request.session:
            return render(request, 'settings.html',
                          {'username': request.user.username, 'db_host_url': request.session['host_url'],
                           'db_name': request.session['db_name'], 'db_username': request.session['username'],
                           'db_password': request.session['password']})
        else:
            return render(request, 'settings.html', {'username': request.user.username, 'db_host_url': '',
                                                     'db_name': '', 'db_username': '', 'db_password': ''})


def render_auth_page(request):
    logout(request)
    if request.method == 'POST':
        username = request.POST["username"]
        password = request.POST["password"]
        password2 = request.POST["password2"]
        is_registering = "registration" in request.POST
        if not is_registering:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('main')
            else:
                return render(request, 'auth.html', {'error': 'invalid login or password'})
        else:
            if password2 != password:
                return render(request, 'auth.html', {'error': 'password mismatch'})
            if len(User.objects.filter(username=username)) != 0:
                return render(request, 'auth.html', {'error': 'user already exists'})
            user = User.objects.create_user(username, password=password)
            if user is not None:
                login(request, user)
                return redirect('main')
            else:
                return render(request, 'auth.html', {'error': 'error while registering'})
    elif request.method == 'GET':
        return render(request, 'auth.html')
