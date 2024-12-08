INSERT INTO permissions (code)
VALUES 
    ('comments:read'),
    ('comments:write');

DELETE FROM permissions 
WHERE code IN ('comments:read', 'comments:write');
