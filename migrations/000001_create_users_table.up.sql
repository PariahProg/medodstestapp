CREATE TABLE IF NOT EXISTS public."users"
(
    id bigserial NOT NULL,
    guid uuid NOT NULL,
    token text COLLATE pg_catalog."default",
    email text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT "user_pkey" PRIMARY KEY (id)
);