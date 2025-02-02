#使用中序后序求前序遍历
class TreeNode:
    def __init__(self, x):
        self.val = x
        self.left = None
        self.right = None


class Solution:
    def reConstructBinaryTree(self, post, tin):
        if len(post) == 0:
            return None
        root = TreeNode(post[-1])
        TinIndex = tin.index(post[-1])
        root.left = self.reConstructBinaryTree(post[0:TinIndex], tin[0:TinIndex])
        root.right = self.reConstructBinaryTree(post[TinIndex:len(post) - 1], tin[TinIndex + 1:])
        return root

    def PreTraversal(self, root):
        if root != None:
            print(root.val,end="")
            self.PreTraversal(root.left)
            self.PreTraversal(root.right)

strm="2f0t02T{hcsiI_SwA__r7Ee}"
stre="20f0Th{2tsIS_icArE}e7__w"
post = list(stre)#后序
tin = list(strm)#中序

S = Solution()
root = S.reConstructBinaryTree(post, tin)
S.PreTraversal(root)
