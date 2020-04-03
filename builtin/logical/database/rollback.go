package database

import (
	"context"

	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

// WAL storage key used for root credential rotations
const rootWALKey = "rootRotationKey"

type rotateCredentialsWAL struct {
	ConnectionName string
	Username    string
	NewPassword string
	OldPassword string
}

// TODO: HA and Replication scenarios? Only leader?
// TODO: Use statements in SetCredentials()?
func (b *databaseBackend) walRollback(ctx context.Context, req *logical.Request, kind string,
	data interface{}) error {
	if kind != rootWALKey {
		return nil
	}

	var entry rotateCredentialsWAL
	if err := mapstructure.Decode(data, &entry); err != nil {
		b.Logger().Info("error decoding WAL data", "data", data)
		return err
	}

	config, err := b.DatabaseConfig(ctx, req.Storage, entry.ConnectionName)
	if err != nil {
		return err
	}
	config.ConnectionDetails["username"] = entry.Username
	config.ConnectionDetails["password"] = entry.NewPassword

	// Get a new connection using the configuration using new rotated credentials
	dbc, err := b.GetConnectionWithConfig(ctx, entry.ConnectionName, config)
	if err != nil {
		return err
	}
	defer func() {
		if err := b.ClearConnection(entry.ConnectionName); err != nil {
			b.Logger().Error("error closing database plugin connection", "err", err)
		}
	}()

	// Restore password to that before the root credential rotation
	rotationStatements := dbplugin.Statements{Rotation:config.RootCredentialsRotateStatements}
	_, _, err = dbc.SetCredentials(ctx, rotationStatements, dbplugin.StaticUserConfig{
		Username: entry.Username,
		Password: entry.OldPassword,
	})
	if err != nil {
		return err
	}

	return nil
}
