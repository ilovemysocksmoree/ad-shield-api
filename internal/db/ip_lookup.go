package db

import (
	"context"
	"fmt"
	"time"

	"github.com/bob17/adpis/internal/logger"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type GeoInfo struct {
	Country      string  `json:"country" bson:"country"`
	CountryCode  string  `json:"country_code" bson:"country_code"`
	Region       string  `json:"region" bson:"region"`
	City         string  `json:"city" bson:"city"`
	Zip          string  `json:"zip" bson:"zip"`
	Latitude     float64 `json:"latitude" bson:"latitude"`
	Longitude    float64 `json:"longitude" bson:"longitude"`
	Timezone     string  `json:"timezone" bson:"timezone"`
	ISP          string  `json:"isp" bson:"isp"`
	Organization string  `json:"organization" bson:"organization"`
	ASN          string  `json:"asn" bson:"asn"`
}

type LookupResult struct {
	ID        bson.ObjectID `json:"id" bson:"_id,omit"`
	Target    string        `json:"target" bson:"target"`
	IP        string        `json:"ip" bson:"ip"`
	GeoInfo   *GeoInfo      `json:"geo_info" bson:"geo_info"`
	Hostnames []string      `json:"hostnames" bson:"hostnames"`
	CreatedAt time.Time     `json:"created_at" bson:"created_at"`
	CreatedBy bson.ObjectID `json:"created_by" bson:"createdy_by"`
}

type LookupStore struct {
	col    *mongo.Collection
	logger logger.Logger
}

func NewLookupStore(c *mongo.Client, dbName string, logger logger.Logger) *LookupStore {
	col := c.Database(dbName).Collection("ip_lookup")
	return &LookupStore{
		col:    col,
		logger: logger,
	}
}

func (il *LookupStore) AddNewIPLookUpData(ctx context.Context, docs LookupResult) error {
	if docs.ID.IsZero() {
		docs.ID = bson.NewObjectID()
	}

	if docs.CreatedBy.IsZero() {
		return fmt.Errorf("user id is invalid")
	}

	resp, err := il.col.InsertOne(ctx, docs)
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("document already exist in collection ip_lookup")
	}

	if err != nil {
		return err
	}

	if !resp.Acknowledged {
		return fmt.Errorf("unable to insert as database returned acknowledgement of false")
	}

	return nil
}

func (il *LookupStore) GetAllIPLookupHistory(ctx context.Context, limit, skip int64) ([]LookupResult, error) {
	var lookupResp []LookupResult
	opts := options.Find()
	opts.SetLimit(limit)
	opts.SetSkip(skip)

	cursor, err := il.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &lookupResp); err != nil {
		return nil, nil
	}

	return lookupResp, nil
}

func (il *LookupStore) GetAIPLookupByID(ctx context.Context, id bson.ObjectID) (*LookupResult, error) {
	var docs LookupResult
	if err := il.col.FindOne(ctx, bson.M{"_id": id}).Decode(&docs); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}

		return nil, err
	}

	return &docs, nil
}

func (il *LookupStore) DeleteIPLookup(ctx context.Context, id bson.ObjectID) error {
	resp, err := il.col.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}

	if resp.DeletedCount == 0 {
		return fmt.Errorf("unable to delete document with provided ID")
	}

	return nil
}
