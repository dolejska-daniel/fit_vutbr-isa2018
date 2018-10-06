// ht.h
// IAL, 31.10.2017
// ISA, 06.10.2018
// Author: Daniel Dolejska, FIT

#ifndef _HASHTABLE_H_
#define _HASHTABLE_H_

#include <stdlib.h>
#include <string.h>


#define ITEM_STATUS_CREATED 0xa0
#define ITEM_STATUS_UPDATED 0xa1

#define MAX_HTSIZE 101	///< Velikost hashovaci tabulky

extern unsigned int HTSIZE;


typedef char* tKey;	///< Typ klice

typedef int tData;	///< Typ obsahu

/**
 * Datova polozka
 */
 typedef struct tHTItem{
	tKey key;	///< Klic
	tData data;	///< Obsah
	struct tHTItem* ptrnext;	///< Ukazatel na dalsi synonymum
} tHTItem;

 /**
  * Tabulka
  */
typedef tHTItem* tHTable[MAX_HTSIZE];


/**
 * Hashovaci funkce
 *
 * @param key
 * @return int
 */
int hashCode ( tKey key );

/**
 *
 * @param ptrht
 */
void htInit ( tHTable* ptrht );

/**
 *
 * @param ptrht
 * @param key
 * @return tHTItem
 */
tHTItem* htSearch ( tHTable* ptrht, tKey key );

/**
 *
 * @param ptrht
 * @param key
 * @param data
 */
void htInsert ( tHTable* ptrht, tKey key, tData data );

/**
 *
 * @param ptrht
 * @param key
 * @return tData
 */
tData* htRead ( tHTable* ptrht, tKey key );

/**
 *
 * @param ptrht
 * @param key
 */
void htDelete ( tHTable* ptrht, tKey key );

/**
 *
 * @param ptrht
 */
void htClearAll ( tHTable* ptrht );

/**
 *
 * @param ptrht
 * @param cb
 */
void htWalk( tHTable* ptrht, void (*cb)(tKey, tData));

/**
 *
 * @param ptrht
 * @param key
 */
unsigned int htIncrease( tHTable* ptrht, tKey key );

#endif
