package main

import (
 "crypto/sha256"
 "encoding/hex"
 "testing"
)

func TestInventoryDigestCanonicalNumericOrder(t *testing.T) {
 entries:=[]inventoryEntry{{Number:10,Size:59},{Number:2,Size:41}}
 actual,err:=inventoryDigest(entries)
 if err!=nil {t.Fatal(err)}
 // The canonical bytes are also reproducible directly from the immutable S3
 // ledger, independent of Pebble's level iteration order and filename padding.
 expectedBytes:=sha256.Sum256([]byte("2\t41\n10\t59\n"))
 expected:=hex.EncodeToString(expectedBytes[:])
 if actual!=expected {t.Fatalf("digest %s, want canonical %s",actual,expected)}
 reversed,err:=inventoryDigest([]inventoryEntry{{Number:2,Size:41},{Number:10,Size:59}})
 if err!=nil || reversed!=actual {t.Fatalf("digest depends on inventory ordering: %s, %v",reversed,err)}
 if entries[0].Number!=10 {t.Fatal("hashing unexpectedly mutated caller inventory")}
}

func TestInventoryDigestDetectsEqualAggregateSubstitution(t *testing.T) {
 original,err:=inventoryDigest([]inventoryEntry{{Number:2,Size:41},{Number:10,Size:59}})
 if err!=nil {t.Fatal(err)}
 variants:=[][]inventoryEntry{
  {{Number:3,Size:41},{Number:10,Size:59}}, // Same count and bytes, replaced object.
  {{Number:2,Size:40},{Number:10,Size:60}}, // Same count and total, changed sizes.
 }
 for _,entries:=range variants {
  changed,err:=inventoryDigest(entries)
  if err!=nil {t.Fatal(err)}
  if changed==original {t.Fatal("same-count/same-total substitution was not detected")}
 }
}

func TestInventoryDigestRejectsDuplicateFileNumbers(t *testing.T) {
 if _,err:=inventoryDigest([]inventoryEntry{{Number:2,Size:41},{Number:2,Size:59}});err==nil {
  t.Fatal("duplicate referenced SST file number was accepted")
 }
}
