// ht.c
// IAL, 31.10.2017
// ISA, 06.10.2018
// Author: Daniel Dolejska, FIT

#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "ht.h"
#include "macros.h"


unsigned int HTSIZE = MAX_HTSIZE;

int hashCode ( tKey key )
{
	assert(key != NULL);

	int retval = 1;
	int keylen = strlen(key);
	for ( int i = 0; i < keylen; i++ )
		retval += key[i];

	return ( retval % HTSIZE );
}

void htInit ( tHTable* ptrht )
{
	assert(ptrht != NULL);

	for(unsigned index = 0; index < HTSIZE; index++)
        (*ptrht)[index] = NULL;
}

tHTItem* htSearch ( tHTable* ptrht, tKey key )
{
	assert(ptrht != NULL);
	assert(key != NULL);

	int hash = hashCode(key);
	tHTItem *item = (*ptrht)[hash];

	while (item != NULL && strcmp(item->key, key) != 0)
		item = item->ptrnext;

	return item;
}

void htInsert ( tHTable* ptrht, tKey key, tData data )
{
	assert(ptrht != NULL);
	assert(key != NULL);

	tHTItem* item = htSearch(ptrht, key);
	if (item != NULL)
	{
		item->data = data;
		return;
	}

	int hash = hashCode(key);
	tHTItem *nextItem = (*ptrht)[hash];
	item = malloc(sizeof(tHTItem));
	if (item == NULL)
	{
		ERR("Failed to allocate memory for hash table item...\n");
		perror("malloc");
		return;
	}

	item->key = key;
	item->data = data;
	item->ptrnext = nextItem;
	(*ptrht)[hash] = item;
}

tData* htRead ( tHTable* ptrht, tKey key )
{
	assert(ptrht != NULL);
	assert(key != NULL);

	tHTItem* item = htSearch(ptrht, key);
	if (item != NULL)
		return &(item->data);

	return NULL;
}

void htDelete ( tHTable* ptrht, tKey key )
{
	assert(ptrht != NULL);
	assert(key != NULL);

	int hash = hashCode(key);
	tHTItem *prevItem = NULL;
	tHTItem *item = (*ptrht)[hash];

	while (item != NULL && strcmp(item->key, key) != 0)
	{
		prevItem = item;
		item = item->ptrnext;
	}

	if (item != NULL)
	{
		//	polozka k odstraneni byla nalezena
		if (prevItem != NULL)
		{
			//	existuje predchozi polozka (ukazatele musi byt aktualizovany)
			prevItem->ptrnext = item->ptrnext;
		}
		else
        {
            //  neexistuje predchozi polozka, tato je nejvyssi
            (*ptrht)[hash] = item->ptrnext;
        }
		free(item);
	}
}

void htClearAll ( tHTable* ptrht )
{
	assert(ptrht != NULL);

	tHTItem *item;
	tHTItem *nextItem;
	for (unsigned index = 0; index < HTSIZE; index++)
	{
		item = (*ptrht)[index];
        while(item != NULL)
        {
            nextItem = item->ptrnext;
            free(item->key);
            free(item);
            item = nextItem;
        }
		(*ptrht)[index] = NULL;
	}
}

void htWalk( tHTable* ptrht, void (*cb)(tKey, tData))
{
	assert(ptrht != NULL);

	tHTItem *item;
	for (unsigned index = 0; index < HTSIZE; index++)
	{
		item = (*ptrht)[index];
		while(item != NULL)
		{
			(*cb)(item->key, item->data);
			item = item->ptrnext;
		}
	}
}

unsigned int htIncrease( tHTable* ptrht, tKey key )
{
	assert(ptrht != NULL);
	assert(key != NULL);

	tHTItem *item = htSearch(ptrht, key);
	if (item == NULL)
	{
		htInsert(ptrht, key, 1);
		return ITEM_STATUS_CREATED;
	}

	item->data++;
	return ITEM_STATUS_UPDATED;
}
