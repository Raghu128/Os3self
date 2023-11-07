#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

struct Segment {
    // int data;
    int size;
    void* mems_virtual_address;
    void* mems_physical_address;
    int is_process;
    struct Segment* next;
    struct Segment* prev;
};
typedef struct Segment Segment;

struct Node {
    struct Segment* head;
    struct Segment* tail;
    int size;
    void* v_start;
    struct Node* next;
    struct Node* prev;
};
typedef struct Node Node;

size_t node_size = (size_t)sizeof(Node);
size_t segment_size = (size_t)sizeof(Segment);

Node* free_list;
void* mems_virtual_start; 

void mems_init() {
    free_list = NULL;
    mems_virtual_start = 1000;
}

Node* find_suitable_segment(size_t size) {
    Node* trav = free_list;

    while(trav) {
        Segment* seg = trav->head;
        while(seg) {
            if(seg->is_process == 0 && seg->size >= size) {
                return trav;
            }
            seg = seg->next;
        }
        trav = trav->next;
    }

    return NULL;
}

 Segment* create_new_segment(void* v_ptr, size_t size) {
    void* p_ptr = mmap(NULL, segment_size + size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    Segment* new_segment = p_ptr;
    if(new_segment == NULL) {
        perror("error");
        return NULL;
    }
    new_segment->mems_virtual_address = v_ptr ;
    new_segment->mems_physical_address = p_ptr; 
    new_segment->size = size;
    new_segment->is_process = 1;
    new_segment->next = NULL;
    new_segment->prev = NULL;

    return new_segment;
}


void* split_hole(Segment* hole, size_t allocated_size) {
    Segment* allocated_segment = create_new_segment(hole->mems_virtual_address, allocated_size);
    allocated_segment->is_process = 1;
    hole->size -= allocated_size;
    hole->mems_virtual_address = (hole->mems_virtual_address + allocated_size);
    if(hole->prev != NULL) {
        hole->prev->next = allocated_segment;
    }
    allocated_segment->next = hole;
    allocated_segment->prev = hole->prev;
    hole->prev = allocated_segment;

    return allocated_segment->mems_virtual_address;
}


void* allocate_segments(Node* node, size_t size)  {
    Segment* seg = node->head;
        while(seg) {
            if(seg->is_process == 0 && seg->size > size) {
                return split_hole(seg, size);
            }
            else if(seg->is_process == 0 && seg->size == size) {
                seg->is_process = 1;
                return seg->mems_virtual_address;
            }
            seg = seg->next;
        }


    // seg = create_new_segment(node->tail->mems_virtual_address + size, size);

    // node->tail->next = seg;
    // seg->prev = node->tail;
    // seg->next = NULL;
    // node->tail = seg;
    // return seg->mems_virtual_address;
}



Node* lastNode() {
    Node* ans = free_list;
    if(ans == NULL)
        return NULL;

    while(ans->next)
        ans = ans->next;

    return ans;
}

Node* create_new_node(size_t n_size) {
    void* new_mems_virtual_address = mmap(NULL, node_size + n_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_mems_virtual_address == MAP_FAILED) {
        perror("mmap error");
        exit(1);
    }
    Node* new_node = (Node*)new_mems_virtual_address;
    new_node->v_start = mems_virtual_start;
    new_node->size = n_size;
    new_node->head = NULL;
    new_node->tail = NULL; 

    Node* lastnode = lastNode();
    mems_virtual_start += n_size;

    if (lastnode == NULL) {
        free_list = new_node;
        return new_node;
    }
    lastnode->next = new_node;
    new_node->prev = lastnode;
    new_node->next = NULL;

    if (lastnode != NULL) {
        free_list->prev = new_node;
    }

    return new_node;
}

void* mems_malloc(size_t size) {
    size_t node_size = size;

    if (size % PAGE_SIZE != 0) {
        node_size = (size / PAGE_SIZE + 1) * PAGE_SIZE;
    }
    Node* node = find_suitable_segment(size);

    if (node) {
        return allocate_segments(node, size);
    } else {
        Node* new_node = create_new_node(node_size);
        if(new_node == NULL) {
            return -1;
        }
        size_t n_v_ptr = (unsigned int)new_node->v_start;
        Segment* seg = create_new_segment(n_v_ptr, size);    
        Segment* remain = create_new_segment(n_v_ptr + size, new_node->size - size); 
        remain->is_process = 0;   
        seg->next = remain;
        remain->prev = seg;  
        new_node->tail = seg;
        new_node->head = seg;       
        return seg->mems_virtual_address;
    }
}

Segment* find_segment_by_virtual_address(void* v_ptr) {
    Node* current_node = free_list;
    while (current_node != NULL) {
        Segment* current_segment = current_node->head;
        while (current_segment != NULL) {
            if (current_segment->mems_virtual_address <= v_ptr && (current_segment->mems_virtual_address + current_segment->size) > v_ptr) {
                
                return current_segment; 
            }
            current_segment = current_segment->next;
        }
        current_node = current_node->next;
    }
    return NULL; 
}

void* mems_get(void* v_ptr) {
    Segment* segment = find_segment_by_virtual_address(v_ptr);
    if (segment) {
        //  printf(" vir %lld\n", segment->mems_physical_address + (v_ptr - segment->mems_virtual_address));
        return segment->mems_physical_address + (v_ptr - segment->mems_virtual_address);
    } else {
        printf("Invalid MeMS virtual address for mems_get: %ld\n", v_ptr);
        return NULL;
    }
}

void mems_print_stats() {
    int mapped_pages = 0;
    long long int unused_memory = 0;
    Node* current_node = free_list;
    if(current_node == NULL) {
        printf("Unmapped all memmory");
        return;
    }

    while (current_node != NULL) {
        printf("Node[%lld:%lld] ->", current_node->v_start, current_node->size + current_node->v_start-1);

        Segment* current_segment = current_node->head;
        while (current_segment != NULL) {
            printf(" %s", (current_segment->is_process == 1) ? "P" : "H");
            printf("[%lld", current_segment->mems_virtual_address);
            printf(":%lld] <-> ", (size_t)current_segment->mems_virtual_address + (size_t)current_segment->size-1);
            if(current_segment->is_process == 0)
                unused_memory += current_segment->size;
            // if(current_segment->next == NULL) {
            //     printf("H[%lld:%lld] <->",current_segment->mems_virtual_address + current_segment->size, current_node->size + current_node->v_start);
            //     unused_memory += current_node->size + current_node->v_start - current_segment->mems_virtual_address - current_segment->size;
            // }

            current_segment = current_segment->next;
        }
        printf(" NULL\n");
        mapped_pages++;
        current_node = current_node->next;
    }

    printf("Mapped Pages: %d\n", mapped_pages);
    printf("Unused Memory: %lldbytes\n", unused_memory);
}



void manage_free_list() {
    Node* current_node = free_list;
    while (current_node != NULL) {
        Segment* current_segment = current_node->head;
        while (current_segment != NULL) {
            if (current_segment->is_process == 0) {

                if (current_segment->next != NULL && current_segment->next->is_process == 0) {
                    current_segment->size += current_segment->next->size;
                    current_segment->next = current_segment->next->next;
                    if (current_segment->next != NULL) {
                        current_segment->next->prev = current_segment;
                    }
                }
            }
            current_segment = current_segment->next;
        }
        current_node = current_node->next;
    }
}


void mems_finish() {
    Node* current_node = free_list;
    while (current_node != NULL) {
        Segment* current_segment = current_node->head;
        current_node->head = NULL;
        current_node->tail = NULL;
        while (current_segment != NULL) {
            void* mems_virtual_address = current_segment->mems_physical_address;
            int size = current_segment->size;
            
            current_segment = current_segment->next;
            if (munmap(mems_virtual_address, size) == -1) {
                perror("munmap error");
                exit(1);
            }
        }
        current_node = current_node->next;
    }
    free_list = NULL;
}


void mems_free(void* ptr) {
    Segment* segment = find_segment_by_virtual_address(ptr);
    if (segment) {
        segment->is_process = 0;
        manage_free_list();
    } else {
        fprintf(stderr, "Invalid MeMS virtual address for mems_free: %p\n", ptr);
    }
}
