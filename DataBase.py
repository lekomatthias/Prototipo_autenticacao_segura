import sqlite3

class DataBase:
    def __init__(self, db_name="dados.db"):
        self.db_name = db_name
        self._create_table()

    def _create_table(self):
        with sqlite3.connect(self.db_name) as con:
            cur = con.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario TEXT UNIQUE,
                    senha TEXT
                )
            ''')
            con.commit()

    def append(self, usuario, senha):
        try:
            with sqlite3.connect(self.db_name) as con:
                cur = con.cursor()
                cur.execute("INSERT INTO usuarios (usuario, senha) VALUES (?, ?)", (usuario.strip(), senha.strip()))
                con.commit()
                return True
        except sqlite3.IntegrityError:
            print(f"Usuário '{usuario}' já existe.")
            return False

    def remove(self, usuario):
        with sqlite3.connect(self.db_name) as con:
            cur = con.cursor()
            cur.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario.strip(),))
            con.commit()
            return cur.rowcount > 0

    def list_users(self):
        with sqlite3.connect(self.db_name) as con:
            cur = con.cursor()
            cur.execute("SELECT usuario FROM usuarios")
            return [row[0] for row in cur.fetchall()]

    def check(self, usuario, senha):
        with sqlite3.connect(self.db_name) as con:
            cur = con.cursor()
            cur.execute("SELECT senha FROM usuarios WHERE usuario = ?", (usuario.strip(),))
            row = cur.fetchone()
            return row is not None and row[0].strip() == senha.strip()


if __name__ == "__main__":

    def Test():
        '''Teste'''
        
        db = DataBase()

        db.append("alice", "abcd")
        db.append("bob", "1234")
        print(db.list_users())  # ['alice', 'bob']
        print(db.check("bob", "1234"))  # True
        # print(db.remove("alice"))  # True
    
    Test()

