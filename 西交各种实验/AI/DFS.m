clc
clear
close
s0=textread('start.txt');
target=[1 2 3;8 0 4;7 6 5];
open={s0};
father={s0};%已遍历结点
treenode={};%结点
node=0;%结点指针
n=0;%加入close表的结点数
count=1;%被扩展出的结点数
while(1)
    close=open(1);
    open(1)=[];
    treenode=[treenode close];
    n=n+1;
    if close{1}==target;
          close{1}
          "The search tree has been found, it is printing now"
        break
    else
        y=extend(close{1});
        yy=cellxor(y,father);
        mem(n)=size(yy,2);
        father=[father,yy];
        if(n==1)
            rootnode=1;
            node(count+1:count+size(yy,2))=1;
        elseif(n==2)
            rootnode=2;
            node(count+1:count+size(yy,2))=rootnode;
        else
            rootnode=rootnode+mem(n-2);
            node(count+1:count+size(yy,2))=rootnode;
        end        
        count=count+size(yy,2);
        open=[yy open];
    end
end
cm=zeros(count,count);
for i=2:count
    cm(node(i),i)=1;
end
for i=1:count
temp=father{i};
temp=temp';
num(i,:)=temp(:);
id{i}=[num2str(num(i,1:3)) ' # ' num2str(num(i,4:6)) ' # ' num2str(num(i,7:9))];
end    
bg=biograph(cm,id);
view(bg)