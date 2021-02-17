import os
import hashlib
from enum import Enum
from pathlib import Path

import psycopg2


class State(Enum):
    NEW = 1
    CONNECTED = 2
    ERROR = 3


__db = None
__db_state = State.NEW


def db():
    global __db
    global __db_state

    if __db_state == State.NEW:
        connect_uri = os.environ.get("POSTGRES_URI")

        if not connect_uri:
            __db_state = State.ERROR
            return None

        try:
            __db = psycopg2.connect(connect_uri)
            __db_state = State.CONNECTED
        except psycopg2.Error as ex:
            print(ex)
            __db_state = State.ERROR

    return __db


def upload(name: str, asm: Path):
    conn = db()
    if conn:
        cursor = conn.cursor()

        # Upsert assembly contents to `asm' table.
        with open(asm, "rb") as f:
            contents = f.read()
            checksum = hashlib.md5(contents).hexdigest()
            cursor.execute(
                """
                INSERT INTO asm (checksum, content)
                VALUES (%s, %s)
                ON CONFLICT (checksum)
                DO UPDATE SET updated_at = NOW()
                RETURNING assembly_id
            """,
                (checksum, contents),
            )
            assembly_id = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT INTO disassembled (name, assembly_id)
            VALUES (%s, %s)
        """,
            (name, assembly_id),
        )

        conn.commit()


# if __name__ == '__main__':
#     upload("ex1", "ex.asm")
