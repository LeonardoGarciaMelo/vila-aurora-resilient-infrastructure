-- Legacy database reproduced for INC-VA-0712. Intentionally weak, synthetic data only.
CREATE TABLE usuarios (id SERIAL PRIMARY KEY, username TEXT, nome TEXT, email TEXT, telefone TEXT, senha_md5 TEXT, perfil TEXT);
CREATE TABLE acessos (id SERIAL PRIMARY KEY, data TIMESTAMPTZ, local TEXT, cracha TEXT);
CREATE TABLE agendamento_bomba (id INT PRIMARY KEY, espaco TEXT, hora_inicio INT, hora_fim INT, ligada BOOLEAN);
INSERT INTO agendamento_bomba VALUES (1, 'escola', 6, 7, false);
