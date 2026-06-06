SELECT drvd.[Id], drvd.[Name], drvd.[Amount], drvd.[CreatedOn]
FROM (VALUES
    (0, 'Alice',   100.00, '2026-01-15'),
    (1, 'Bob',     250.50, '2026-02-03'),
    (2, 'Carol',    75.25, '2026-02-20'),
    (3, 'Dan',     420.00, '2026-03-11'),
    (4, 'Erin',     12.99, '2026-04-01')
) drvd([Id], [Name], [Amount], [CreatedOn]);
